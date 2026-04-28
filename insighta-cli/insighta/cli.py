"""
insighta — CLI for Insighta Labs+
"""
import json
import os
import sys
import hashlib
import base64
import secrets
import socket
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

import click
import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Spinner, Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()

# ── Config ────────────────────────────────────────────────────────────────────

CREDS_PATH = Path.home() / ".insighta" / "credentials.json"
API_BASE = os.environ.get("INSIGHTA_API_URL", "https://hng-stage-3-lqvd.vercel.app/")
API_HEADERS = {"X-API-Version": "1"}


def _save_creds(data: dict):
    CREDS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CREDS_PATH.write_text(json.dumps(data, indent=2))


def _load_creds() -> dict | None:
    if not CREDS_PATH.exists():
        return None
    try:
        return json.loads(CREDS_PATH.read_text())
    except Exception:
        return None


def _clear_creds():
    if CREDS_PATH.exists():
        CREDS_PATH.unlink()


def _refresh_tokens(creds: dict) -> dict | None:
    """Attempt to refresh access token. Returns updated creds or None."""
    try:
        resp = httpx.post(
            f"{API_BASE}/auth/refresh",
            json={"refresh_token": creds.get("refresh_token", "")},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            creds["access_token"] = data["access_token"]
            creds["refresh_token"] = data["refresh_token"]
            _save_creds(creds)
            return creds
    except Exception:
        pass
    return None


def _get_auth_headers() -> dict:
    """Return auth + API version headers, refreshing token if needed."""
    creds = _load_creds()
    if not creds:
        console.print("[red]Not logged in. Run:[/red] insighta login")
        sys.exit(1)

    headers = {**API_HEADERS, "Authorization": f"Bearer {creds['access_token']}"}

    # Try a quick check — if 401, refresh
    return headers, creds


def _request(method: str, path: str, **kwargs) -> httpx.Response:
    """Make authenticated request, auto-refreshing on 401."""
    creds = _load_creds()
    if not creds:
        console.print("[red]Not logged in. Run:[/red] insighta login")
        sys.exit(1)

    headers = {**API_HEADERS, "Authorization": f"Bearer {creds['access_token']}"}
    url = f"{API_BASE}{path}"

    resp = httpx.request(method, url, headers=headers, timeout=15.0, **kwargs)

    if resp.status_code == 401:
        # Try refresh
        console.print("[yellow]Token expired, refreshing...[/yellow]")
        new_creds = _refresh_tokens(creds)
        if not new_creds:
            _clear_creds()
            console.print("[red]Session expired. Please run:[/red] insighta login")
            sys.exit(1)
        headers["Authorization"] = f"Bearer {new_creds['access_token']}"
        resp = httpx.request(method, url, headers=headers, timeout=15.0, **kwargs)

    return resp


# ── PKCE helpers ──────────────────────────────────────────────────────────────

def _generate_pkce() -> tuple[str, str, str]:
    """Return (state, code_verifier, code_challenge)."""
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return state, code_verifier, code_challenge


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


# ── Local callback server ─────────────────────────────────────────────────────

class _CallbackResult:
    code: str | None = None
    state: str | None = None
    error: str | None = None


def _start_callback_server(port: int, result: _CallbackResult, stop_event: threading.Event):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # silence server logs

        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            result.code = params.get("code", [None])[0]
            result.state = params.get("state", [None])[0]
            result.error = params.get("error", [None])[0]

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html><body style="font-family:sans-serif;text-align:center;padding:60px">
                <h2>&#10003; Authenticated!</h2>
                <p>You can close this tab and return to the terminal.</p>
                </body></html>
            """)
            stop_event.set()

    server = HTTPServer(("localhost", port), Handler)
    server.timeout = 1
    while not stop_event.is_set():
        server.handle_request()
    server.server_close()


# ── CLI groups ────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """Insighta Labs+ CLI"""
    pass


# ── AUTH commands ─────────────────────────────────────────────────────────────

@cli.command()
def login():
    """Authenticate via GitHub OAuth."""
    port = _find_free_port()
    state, code_verifier, code_challenge = _generate_pkce()

    callback_url = f"http://localhost:{port}/callback"
    params = urlencode({
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "cli_callback": callback_url,
    })
    auth_url = f"{API_BASE}/auth/github?{params}"

    console.print(f"\n[bold cyan]Opening GitHub OAuth in your browser...[/bold cyan]")
    console.print(f"[dim]If it doesn't open, visit:[/dim] {auth_url}\n")
    webbrowser.open(auth_url)

    # Start local callback server
    result = _CallbackResult()
    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=_start_callback_server,
        args=(port, result, stop_event),
        daemon=True,
    )
    server_thread.start()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Waiting for GitHub callback...", total=None)
        stop_event.wait(timeout=120)

    if not result.code:
        console.print("[red]Login timed out or was cancelled.[/red]")
        sys.exit(1)

    if result.state != state:
        console.print("[red]State mismatch — possible CSRF attack. Aborting.[/red]")
        sys.exit(1)

    # Exchange code with backend
    with Progress(SpinnerColumn(), TextColumn("Exchanging code..."), transient=True) as p:
        p.add_task("", total=None)
        try:
            resp = httpx.get(
                f"{API_BASE}/auth/github/callback",
                params={
                    "code": result.code,
                    "state": result.state,
                    "code_verifier": code_verifier,
                },
                timeout=15.0,
                follow_redirects=True,
            )
        except httpx.RequestError as e:
            console.print(f"[red]Network error:[/red] {e}")
            sys.exit(1)

    if resp.status_code != 200:
        console.print(f"[red]Auth failed:[/red] {resp.text}")
        sys.exit(1)

    data = resp.json()
    _save_creds({
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "username": data["user"]["username"],
        "role": data["user"]["role"],
    })

    console.print(f"\n[bold green]✓ Logged in as @{data['user']['username']}[/bold green] ([dim]{data['user']['role']}[/dim])\n")


@cli.command()
def logout():
    """Revoke session and clear local credentials."""
    creds = _load_creds()
    if creds:
        try:
            httpx.post(
                f"{API_BASE}/auth/logout",
                json={"refresh_token": creds.get("refresh_token", "")},
                timeout=10.0,
            )
        except Exception:
            pass
    _clear_creds()
    console.print("[green]✓ Logged out successfully.[/green]")


@cli.command()
def whoami():
    """Show current logged-in user."""
    creds = _load_creds()
    if not creds:
        console.print("[red]Not logged in.[/red]")
        return
    console.print(f"[bold]Username:[/bold] @{creds.get('username', '?')}")
    console.print(f"[bold]Role:[/bold]     {creds.get('role', '?')}")


# ── PROFILES group ────────────────────────────────────────────────────────────

@cli.group()
def profiles():
    """Manage profiles."""
    pass


@profiles.command("list")
@click.option("--gender", default=None)
@click.option("--country", default=None, help="2-letter country code e.g. NG")
@click.option("--age-group", default=None, type=click.Choice(["child", "teenager", "adult", "senior"]))
@click.option("--min-age", default=None, type=int)
@click.option("--max-age", default=None, type=int)
@click.option("--sort-by", default="created_at", type=click.Choice(["age", "created_at", "gender_probability"]))
@click.option("--order", default="asc", type=click.Choice(["asc", "desc"]))
@click.option("--page", default=1, type=int)
@click.option("--limit", default=10, type=int)
def list_profiles(gender, country, age_group, min_age, max_age, sort_by, order, page, limit):
    """List profiles with optional filters."""
    params = {"page": page, "limit": limit, "sort_by": sort_by, "order": order}
    if gender:
        params["gender"] = gender
    if country:
        params["country_id"] = country
    if age_group:
        params["age_group"] = age_group
    if min_age is not None:
        params["min_age"] = min_age
    if max_age is not None:
        params["max_age"] = max_age

    with Progress(SpinnerColumn(), TextColumn("Fetching profiles..."), transient=True) as p:
        p.add_task("", total=None)
        resp = _request("GET", "/api/profiles", params=params)

    if resp.status_code != 200:
        _print_error(resp)
        return

    body = resp.json()
    _print_profiles_table(body)


@profiles.command("get")
@click.argument("profile_id")
def get_profile(profile_id):
    """Get a single profile by ID."""
    with Progress(SpinnerColumn(), TextColumn("Fetching..."), transient=True) as p:
        p.add_task("", total=None)
        resp = _request("GET", f"/api/profiles/{profile_id}")

    if resp.status_code != 200:
        _print_error(resp)
        return

    data = resp.json()["data"]
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=25)
    table.add_column()
    for k, v in data.items():
        table.add_row(k, str(v))
    console.print(table)


@profiles.command("search")
@click.argument("query")
@click.option("--page", default=1, type=int)
@click.option("--limit", default=10, type=int)
def search_profiles(query, page, limit):
    """Natural language search e.g. 'young males from nigeria'."""
    with Progress(SpinnerColumn(), TextColumn("Searching..."), transient=True) as p:
        p.add_task("", total=None)
        resp = _request("GET", "/api/profiles/search", params={"q": query, "page": page, "limit": limit})

    if resp.status_code != 200:
        _print_error(resp)
        return

    _print_profiles_table(resp.json())


@profiles.command("create")
@click.option("--name", required=True, help="Profile name")
def create_profile(name):
    """Create a new profile (admin only)."""
    with Progress(SpinnerColumn(), TextColumn("Creating profile..."), transient=True) as p:
        p.add_task("", total=None)
        resp = _request("POST", "/api/profiles", json={"name": name})

    if resp.status_code not in (200, 201):
        _print_error(resp)
        return

    data = resp.json()["data"]
    console.print(f"\n[bold green]✓ Profile created[/bold green]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=25)
    table.add_column()
    for k, v in data.items():
        table.add_row(k, str(v))
    console.print(table)


@profiles.command("export")
@click.option("--format", "fmt", default="csv", type=click.Choice(["csv"]))
@click.option("--gender", default=None)
@click.option("--country", default=None)
@click.option("--age-group", default=None)
def export_profiles(fmt, gender, country, age_group):
    """Export profiles to CSV."""
    params = {"format": fmt}
    if gender:
        params["gender"] = gender
    if country:
        params["country_id"] = country
    if age_group:
        params["age_group"] = age_group

    with Progress(SpinnerColumn(), TextColumn("Exporting..."), transient=True) as p:
        p.add_task("", total=None)
        resp = _request("GET", "/api/profiles/export", params=params)

    if resp.status_code != 200:
        _print_error(resp)
        return

    # Get filename from Content-Disposition header or generate one
    cd = resp.headers.get("content-disposition", "")
    filename = "profiles_export.csv"
    if "filename=" in cd:
        filename = cd.split("filename=")[-1].strip('"')

    dest = Path.cwd() / filename
    dest.write_bytes(resp.content)
    console.print(f"[bold green]✓ Exported to:[/bold green] {dest}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_profiles_table(body: dict):
    data = body.get("data", [])
    total = body.get("total", len(data))
    page = body.get("page", 1)
    total_pages = body.get("total_pages", 1)

    if not data:
        console.print("[yellow]No profiles found.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    cols = ["id", "name", "gender", "age", "age_group", "country_id", "country_name", "created_at"]
    for col in cols:
        table.add_column(col.replace("_", " ").title(), overflow="fold")

    for p in data:
        if hasattr(p, "__dict__"):
            p = p.__dict__
        elif not isinstance(p, dict):
            p = dict(p)
        table.add_row(*[str(p.get(c, "")) for c in cols])

    console.print(table)
    console.print(f"\n[dim]Page {page} of {total_pages} · {total} total results[/dim]\n")


def _print_error(resp: httpx.Response):
    try:
        msg = resp.json().get("message", resp.text)
    except Exception:
        msg = resp.text
    console.print(f"[red]Error {resp.status_code}:[/red] {msg}")


def main():
    cli()