
import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# Charge explicitement le .env situé à côté de depcheck.py
load_dotenv(BASE_DIR / ".env")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()

GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"

OSV_URL = "https://api.osv.dev/v1/querybatch"

# Token stocké dans le profil Windows de l'utilisateur
TOKEN_FILE = Path.home() / ".depcheck_github_token"

# Dossiers à ignorer pendant le scan
IGNORED_DIRECTORIES = {
    ".git",
    ".github",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


# ============================================================
# UTILS
# ============================================================

def print_banner():
    print("=" * 65)
    print("DEPCheck - Dependency Vulnerability Scanner")
    print("=" * 65)


def save_token(token):
    try:
        TOKEN_FILE.write_text(token, encoding="utf-8")

        # Protection supplémentaire sous Windows/Linux quand possible
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except Exception:
            pass

        print(f"[OK] GitHub token saved to: {TOKEN_FILE}")

    except Exception as e:
        print(f"[ERROR] Cannot save GitHub token: {e}")


def load_token():
    if not TOKEN_FILE.exists():
        return None

    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()

        if token:
            return token

    except Exception as e:
        print(f"[WARNING] Cannot read GitHub token: {e}")

    return None


# ============================================================
# GITHUB OAUTH DEVICE FLOW
# ============================================================

def github_login():
    print()
    print("GitHub OAuth Login")
    print("=" * 65)

    if not GITHUB_CLIENT_ID:
        print("[ERROR] GITHUB_CLIENT_ID is missing.")
        print()
        print("Create a .env file next to depcheck.py:")
        print()
        print("GITHUB_CLIENT_ID=Iv1.xxxxxxxxxxxxxxxxx")
        print()
        print("Use the Client ID of your GitHub OAuth App.")
        print("Do NOT use the Client Secret.")
        return 1

    print(f"[INFO] Client ID detected: {GITHUB_CLIENT_ID[:8]}...")

    # --------------------------------------------------------
    # STEP 1 - Request device code
    # --------------------------------------------------------

    headers = {
        "Accept": "application/json",
        "User-Agent": "depcheck"
    }

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "scope": "repo"
    }

    try:
        response = requests.post(
            GITHUB_DEVICE_CODE_URL,
            params=params,
            headers=headers,
            timeout=20
        )

    except requests.RequestException as e:
        print(f"[ERROR] GitHub OAuth request failed: {e}")
        return 1

    if response.status_code != 200:
        print()
        print("[ERROR] GitHub rejected the OAuth request.")
        print(f"HTTP Status: {response.status_code}")

        try:
            error_data = response.json()

            print()
            print("GitHub response:")
            print(json.dumps(error_data, indent=2))

            error_code = error_data.get("error")

            if error_code == "device_flow_disabled":
                print()
                print("FIX:")
                print("1. Open GitHub.")
                print("2. Go to Settings.")
                print("3. Developer settings.")
                print("4. OAuth Apps.")
                print("5. Open your depcheck OAuth App.")
                print("6. Edit the application.")
                print("7. Enable 'Device Flow'.")
                print("8. Save changes.")

            elif error_code == "incorrect_client_credentials":
                print()
                print("FIX:")
                print("Check GITHUB_CLIENT_ID in your .env file.")
                print("Make sure you are using the OAuth App Client ID.")
                print("Do NOT use the Client Secret.")

        except ValueError:
            print(response.text)

        return 1

    try:
        data = response.json()

    except ValueError:
        print("[ERROR] GitHub returned invalid JSON.")
        print(response.text)
        return 1

    device_code = data.get("device_code")
    user_code = data.get("user_code")
    verification_uri = data.get("verification_uri")
    expires_in = data.get("expires_in", 900)
    interval = data.get("interval", 5)

    if not device_code or not user_code:
        print("[ERROR] GitHub did not return a valid device code.")
        print(json.dumps(data, indent=2))
        return 1

    # --------------------------------------------------------
    # STEP 2 - Display authorization instructions
    # --------------------------------------------------------

    print()
    print("AUTHORIZATION REQUIRED")
    print("-" * 65)
    print(f"Open this URL in your browser:")
    print()
    print(verification_uri)
    print()
    print(f"Enter this code:")
    print()
    print(f"    {user_code}")
    print()
    print(f"The code expires in approximately {expires_in} seconds.")
    print("-" * 65)

    try:
        input("Press ENTER after authorizing the application...")
    except KeyboardInterrupt:
        print()
        print("[INFO] Login cancelled.")
        return 1

    # --------------------------------------------------------
    # STEP 3 - Poll GitHub for access token
    # --------------------------------------------------------

    print()
    print("[INFO] Waiting for GitHub authorization...")

    deadline = time.time() + expires_in

    while time.time() < deadline:

        token_data = {
            "client_id": GITHUB_CLIENT_ID,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        }

        try:
            token_response = requests.post(
                GITHUB_TOKEN_URL,
                data=token_data,
                headers=headers,
                timeout=20
            )

        except requests.RequestException as e:
            print(f"[ERROR] Token request failed: {e}")
            return 1

        try:
            token_json = token_response.json()

        except ValueError:
            print("[ERROR] GitHub returned invalid token response.")
            print(token_response.text)
            return 1

        access_token = token_json.get("access_token")

        if access_token:
            save_token(access_token)

            print()
            print("[SUCCESS] GitHub login successful!")
            return 0

        error = token_json.get("error")

        if error == "authorization_pending":
            print(".", end="", flush=True)
            time.sleep(interval)
            continue

        if error == "slow_down":
            interval += 5
            time.sleep(interval)
            continue

        if error == "expired_token":
            print()
            print("[ERROR] The device code has expired.")
            print("Run the login command again.")
            return 1

        if error == "access_denied":
            print()
            print("[ERROR] GitHub authorization was denied.")
            return 1

        print()
        print("[ERROR] GitHub OAuth failed.")
        print(json.dumps(token_json, indent=2))
        return 1

    print()
    print("[ERROR] OAuth authorization timed out.")
    return 1


# ============================================================
# GITHUB API
# ============================================================

def get_github_token():
    token = load_token()

    if not token:
        print("[ERROR] You are not logged in to GitHub.")
        print()
        print("Run:")
        print("    py .\\depcheck.py login")
        return None

    return token


def github_request(method, url, **kwargs):
    token = get_github_token()

    if not token:
        return None

    headers = kwargs.pop("headers", {})

    headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "depcheck"
    })

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=30,
            **kwargs
        )

    except requests.RequestException as e:
        print(f"[ERROR] GitHub request failed: {e}")
        return None

    if response.status_code == 401:
        print("[ERROR] GitHub token is invalid or expired.")
        print("Run:")
        print("    py .\\depcheck.py login")
        return None

    if response.status_code == 403:
        print("[ERROR] GitHub API permission denied.")
        return None

    if response.status_code == 404:
        print("[ERROR] GitHub resource not found or not accessible.")
        return None

    if not response.ok:
        print(
            f"[ERROR] GitHub API returned "
            f"HTTP {response.status_code}"
        )

        try:
            print(json.dumps(response.json(), indent=2))
        except Exception:
            print(response.text)

        return None

    return response


def github_user():
    response = github_request(
        "GET",
        f"{GITHUB_API_URL}/user"
    )

    if not response:
        return None

    try:
        return response.json()
    except Exception:
        return None


def github_repositories():
    repositories = []
    page = 1

    while True:

        response = github_request(
            "GET",
            f"{GITHUB_API_URL}/user/repos",
            params={
                "visibility": "all",
                "affiliation": "owner,collaborator,organization_member",
                "per_page": 100,
                "page": page
            }
        )

        if not response:
            return repositories

        try:
            page_data = response.json()
        except Exception:
            return repositories

        if not page_data:
            break

        repositories.extend(page_data)

        if len(page_data) < 100:
            break

        page += 1

    return repositories


# ============================================================
# GITHUB CONTENTS
# ============================================================

def github_contents(owner, repo, path=""):
    url = (
        f"{GITHUB_API_URL}/repos/"
        f"{owner}/{repo}/contents/{path}"
    )

    response = github_request("GET", url)

    if not response:
        return None

    try:
        return response.json()
    except Exception:
        return None


def github_file(owner, repo, path):
    data = github_contents(owner, repo, path)

    if not isinstance(data, dict):
        return None

    if data.get("type") != "file":
        return None

    content = data.get("content")

    if not content:
        return None

    try:
        return base64.b64decode(content).decode(
            "utf-8",
            errors="replace"
        )

    except Exception as e:
        print(f"[WARNING] Cannot decode {path}: {e}")
        return None


# ============================================================
# LOCAL DEPENDENCY PARSERS
# ============================================================

def parse_requirements(content):
    dependencies = []

    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # Remove inline comments
        line = line.split("#", 1)[0].strip()

        if "==" not in line:
            continue

        name, version = line.split("==", 1)

        name = name.strip()
        version = version.strip()

        if not name or not version:
            continue

        dependencies.append({
            "name": name,
            "version": version,
            "ecosystem": "PyPI"
        })

    return dependencies


def parse_package_json(content):
    try:
        data = json.loads(content)

    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid package.json: {e}")
        return []

    dependencies = []

    sections = [
        "dependencies",
        "devDependencies"
    ]

    for section in sections:

        section_data = data.get(section, {})

        if not isinstance(section_data, dict):
            continue

        for name, version in section_data.items():

            if not isinstance(version, str):
                continue

            version = version.strip()

            # We only scan exact versions
            if not version:
                continue

            if version.startswith((
                "^",
                "~",
                ">",
                "<",
                "=",
                "*",
                "latest",
                "git+",
                "http"
            )):
                continue

            # Remove npm prefix if present
            if version.startswith("v"):
                version = version[1:]

            # Basic exact semantic version check
            if not version[0].isdigit():
                continue

            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "npm"
            })

    return dependencies


# ============================================================
# OSV SCANNER
# ============================================================

def query_osv(dependencies):
    if not dependencies:
        return []

    queries = []

    for dependency in dependencies:
        queries.append({
            "package": {
                "name": dependency["name"],
                "ecosystem": dependency["ecosystem"]
            },
            "version": dependency["version"]
        })

    try:
        response = requests.post(
            OSV_URL,
            json={"queries": queries},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "depcheck"
            },
            timeout=60
        )

    except requests.RequestException as e:
        print(f"[ERROR] OSV request failed: {e}")
        return []

    if not response.ok:
        print(
            f"[ERROR] OSV returned HTTP "
            f"{response.status_code}"
        )

        try:
            print(response.text)
        except Exception:
            pass

        return []

    try:
        data = response.json()
    except ValueError:
        print("[ERROR] OSV returned invalid JSON.")
        return []

    results = []

    osv_results = data.get("results", [])

    for index, result in enumerate(osv_results):

        if index >= len(dependencies):
            break

        dependency = dependencies[index]

        vulnerabilities = result.get("vulns", [])

        for vulnerability in vulnerabilities:

            results.append({
                "name": dependency["name"],
                "version": dependency["version"],
                "ecosystem": dependency["ecosystem"],
                "id": vulnerability.get("id"),
                "summary": vulnerability.get(
                    "summary",
                    "No description"
                ),
                "details": vulnerability.get(
                    "details",
                    ""
                ),
                "severity": get_severity(vulnerability),
                "references": [
                    ref.get("url")
                    for ref in vulnerability.get(
                        "references",
                        []
                    )
                    if ref.get("url")
                ]
            })

    return results


def get_severity(vulnerability):

    severity_list = vulnerability.get("severity", [])

    if not severity_list:
        return "UNKNOWN"

    for severity in severity_list:

        if severity.get("type") == "CVSS_V3":
            score = severity.get("score", "")

            if score:
                return score

    return "UNKNOWN"


# ============================================================
# DISPLAY RESULTS
# ============================================================

def print_results(results):

    print()
    print("=" * 65)
    print("SCAN RESULTS")
    print("=" * 65)

    if not results:
        print()
        print("[OK] No known vulnerabilities found.")
        return

    print()
    print(f"[WARNING] {len(results)} vulnerability(s) found.")
    print()

    for index, vulnerability in enumerate(results, start=1):

        print("-" * 65)
        print(f"#{index}")
        print(f"Package     : {vulnerability['name']}")
        print(f"Version     : {vulnerability['version']}")
        print(f"Ecosystem   : {vulnerability['ecosystem']}")
        print(f"Vulnerability: {vulnerability['id']}")
        print(f"Severity    : {vulnerability['severity']}")
        print(
            f"Summary     : "
            f"{vulnerability['summary']}"
        )

        references = vulnerability.get("references", [])

        if references:
            print("References  :")

            for reference in references[:5]:
                print(f"  - {reference}")

    print("-" * 65)


# ============================================================
# LOCAL SCAN
# ============================================================

def scan_local_file(file_path):

    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        return 1

    if not path.is_file():
        print(f"[ERROR] Not a file: {path}")
        return 1

    print()
    print(f"[INFO] Scanning: {path}")

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="replace"
        )

    except Exception as e:
        print(f"[ERROR] Cannot read file: {e}")
        return 1

    filename = path.name.lower()

    if filename == "requirements.txt":
        dependencies = parse_requirements(content)

    elif filename == "package.json":
        dependencies = parse_package_json(content)

    else:
        print()
        print("[ERROR] Unsupported dependency file.")
        print()
        print("Supported files:")
        print("  - requirements.txt")
        print("  - package.json")
        return 1

    print(
        f"[INFO] Dependencies detected: "
        f"{len(dependencies)}"
    )

    if not dependencies:
        print("[WARNING] No exact dependencies found.")
        print()
        print("For Python, use:")
        print("    requests==2.32.0")
        print()
        print("For npm, use exact versions:")
        print('    "express": "4.21.2"')
        return 0

    results = query_osv(dependencies)

    return results


# ============================================================
# GITHUB REPOSITORY SCAN
# ============================================================

def find_dependency_files(owner, repo, path=""):
    found = []

    contents = github_contents(
        owner,
        repo,
        path
    )

    if not isinstance(contents, list):
        return found

    for item in contents:

        item_type = item.get("type")
        item_name = item.get("name", "")
        item_path = item.get("path", "")

        if item_type == "file":

            if item_name.lower() in {
                "requirements.txt",
                "package.json"
            }:
                found.append(item_path)

        elif item_type == "dir":

            if item_name in IGNORED_DIRECTORIES:
                continue

            nested = find_dependency_files(
                owner,
                repo,
                item_path
            )

            found.extend(nested)

    return found


def scan_github_repository(repository):

    if "/" not in repository:
        print(
            "[ERROR] Repository must use this format:"
        )
        print()
        print("    OWNER/REPOSITORY")
        print()
        print("Example:")
        print("    octocat/Hello-World")
        return 1

    owner, repo = repository.split("/", 1)

    print()
    print("=" * 65)
    print("GitHub Repository Scan")
    print("=" * 65)
    print()
    print(f"Repository: {owner}/{repo}")

    # Verify repository
    root = github_contents(owner, repo)

    if root is None:
        return 1

    print()
    print("[INFO] Searching dependency files...")

    files = find_dependency_files(
        owner,
        repo
    )

    if not files:
        print()
        print("[WARNING] No supported dependency files found.")
        print()
        print("Supported:")
        print("  - requirements.txt")
        print("  - package.json")
        return 0

    print()
    print(f"[OK] Found {len(files)} dependency file(s):")

    for file in files:
        print(f"  - {file}")

    all_results = []

    # --------------------------------------------------------
    # Scan each dependency file
    # --------------------------------------------------------

    for file_path in files:

        print()
        print("-" * 65)
        print(f"[INFO] Scanning {file_path}")

        content = github_file(
            owner,
            repo,
            file_path
        )

        if content is None:
            continue

        filename = Path(file_path).name.lower()

        if filename == "requirements.txt":
            dependencies = parse_requirements(content)

        elif filename == "package.json":
            dependencies = parse_package_json(content)

        else:
            continue

        print(
            f"[INFO] Dependencies detected: "
            f"{len(dependencies)}"
        )

        if not dependencies:
            continue

        results = query_osv(dependencies)

        for result in results:
            result["file"] = file_path

        all_results.extend(results)

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print()
    print("=" * 65)
    print("GITHUB SCAN RESULTS")
    print("=" * 65)

    if not all_results:
        print()
        print("[OK] No known vulnerabilities found.")
        return all_results

    print()
    print(
        f"[WARNING] "
        f"{len(all_results)} vulnerability(s) found."
    )

    for index, vulnerability in enumerate(
        all_results,
        start=1
    ):

        print()
        print("-" * 65)

        print(f"#{index}")
        print(
            f"File        : "
            f"{vulnerability.get('file', 'N/A')}"
        )
        print(
            f"Package     : "
            f"{vulnerability['name']}"
        )
        print(
            f"Version     : "
            f"{vulnerability['version']}"
        )
        print(
            f"Ecosystem   : "
            f"{vulnerability['ecosystem']}"
        )
        print(
            f"Vulnerability: "
            f"{vulnerability['id']}"
        )
        print(
            f"Severity    : "
            f"{vulnerability['severity']}"
        )
        print(
            f"Summary     : "
            f"{vulnerability['summary']}"
        )

    return all_results


# ============================================================
# REPOSITORIES COMMAND
# ============================================================

def list_repositories():

    print()
    print("=" * 65)
    print("GitHub Repositories")
    print("=" * 65)

    user = github_user()

    if not user:
        return 1

    print()
    print(
        f"Logged in as: "
        f"{user.get('login', 'unknown')}"
    )

    repositories = github_repositories()

    if not repositories:
        print()
        print("[INFO] No repositories found.")
        return 0

    print()

    for index, repository in enumerate(
        repositories,
        start=1
    ):

        visibility = (
            "PRIVATE"
            if repository.get("private")
            else "PUBLIC"
        )

        print(
            f"{index}. "
            f"{repository.get('full_name')} "
            f"[{visibility}]"
        )

    print()
    print(
        f"Total repositories: "
        f"{len(repositories)}"
    )

    return 0


# ============================================================
# JSON OUTPUT
# ============================================================

def output_json(results):

    print()

    print(
        json.dumps(
            results,
            indent=2,
            ensure_ascii=False
        )
    )


# ============================================================
# ARGUMENT PARSER
# ============================================================

def create_parser():

    parser = argparse.ArgumentParser(
        prog="depcheck",
        description=(
            "Dependency vulnerability scanner "
            "for local and GitHub repositories."
        )
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # --------------------------------------------------------
    # scan
    # --------------------------------------------------------

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local dependency file"
    )

    scan_parser.add_argument(
        "dependency_file",
        help=(
            "Path to requirements.txt "
            "or package.json"
        )
    )

    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    # --------------------------------------------------------
    # login
    # --------------------------------------------------------

    subparsers.add_parser(
        "login",
        help="Login with GitHub OAuth"
    )

    # --------------------------------------------------------
    # repos
    # --------------------------------------------------------

    subparsers.add_parser(
        "repos",
        help="List GitHub repositories"
    )

    # --------------------------------------------------------
    # github-scan
    # --------------------------------------------------------

    github_scan_parser = subparsers.add_parser(
        "github-scan",
        help="Scan a GitHub repository"
    )

    github_scan_parser.add_argument(
        "repository",
        help="Repository in OWNER/REPOSITORY format"
    )

    github_scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main():

    parser = create_parser()

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    # --------------------------------------------------------
    # LOGIN
    # --------------------------------------------------------

    if args.command == "login":

        print_banner()

        return github_login()

    # --------------------------------------------------------
    # REPOSITORIES
    # --------------------------------------------------------

    if args.command == "repos":

        print_banner()

        return list_repositories()

    # --------------------------------------------------------
    # LOCAL SCAN
    # --------------------------------------------------------

    if args.command == "scan":

        print_banner()

        result = scan_local_file(
            args.dependency_file
        )

        if isinstance(result, int):
            return result

        results = result

        if args.json:
            output_json(results)
        else:
            print_results(results)

        return 0

    # --------------------------------------------------------
    # GITHUB SCAN
    # --------------------------------------------------------

    if args.command == "github-scan":

        print_banner()

        result = scan_github_repository(
            args.repository
        )

        if isinstance(result, int):
            return result

        if args.json:
            output_json(result)

        return 0

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())