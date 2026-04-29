# Insighta Labs+ — CLI

Globally installable CLI tool for the Insighta Labs+ platform.

## Installation

```bash
# Clone the repo
git clone https://github.com/your-org/hng-stage_3cli
cd insighta-cli

# Install globally (creates the `insighta` command)
pip install -e .
```

After installation, `insighta` is available from any directory.

## Configuration

By default the CLI targets the production backend. To use a different backend:

```bash
export INSIGHTA_API_URL=http://localhost:8000
```

## Authentication

```bash
# Login via GitHub OAuth (opens browser)
insighta login

# Check who's logged in
insighta whoami

# Logout and revoke session
insighta logout
```

### Login Flow (PKCE)
1. CLI generates `state`, `code_verifier`, and `code_challenge`
2. Starts a local HTTP callback server on a random port
3. Opens the GitHub OAuth page in your default browser
4. After GitHub auth, GitHub redirects to `http://localhost:<port>/callback`
5. CLI captures the code, validates the state, sends `code + code_verifier` to backend
6. Backend exchanges the code with GitHub, creates/updates user, issues tokens
7. Tokens are saved to `~/.insighta/credentials.json`

## Token Handling

Credentials are stored at `~/.insighta/credentials.json`:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "username": "your-github-username",
  "role": "analyst"
}
```

- Access tokens expire in **3 minutes**, refresh tokens in **5 minutes**
- On any `401` response, the CLI automatically attempts to refresh
- If refresh fails, credentials are cleared and you're prompted to log in again

## Commands

### Auth
```bash
insighta login                          # GitHub OAuth login
insighta logout                         # Revoke session
insighta whoami                         # Show current user
```

### Profiles
```bash
insighta profiles list                               # All profiles (paginated)
insighta profiles list --gender male                 # Filter by gender
insighta profiles list --country NG                  # Filter by country code
insighta profiles list --age-group adult             # Filter by age group
insighta profiles list --min-age 25 --max-age 40     # Filter by age range
insighta profiles list --sort-by age --order desc    # Sort
insighta profiles list --page 2 --limit 20           # Pagination

insighta profiles get <id>                           # Get profile by ID

insighta profiles search "young males from nigeria"  # Natural language search
insighta profiles search "female adults in Ghana" --page 2

insighta profiles create --name "Harriet Tubman"     # Create profile (admin only)

insighta profiles export --format csv                # Export all to CSV
insighta profiles export --format csv --gender male --country NG  # Filtered export
```

CSV is saved to the **current working directory** with a timestamped filename.

## Output

All results are displayed as rich formatted tables with loading spinners. Errors are clearly displayed with status codes.