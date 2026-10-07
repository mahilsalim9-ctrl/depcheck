import json
import time
from pathlib import Path

import requests
from dotenv import load_dotenv
import os


load_dotenv()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")

DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"

TOKEN_FILE = Path.home() / ".depcheck_github_token"


def save_token(token):
    TOKEN_FILE.write_text(
        json.dumps({"access_token": token}, indent=2),
        encoding="utf-8"
    )


def load_token():
    if not TOKEN_FILE.exists():
        return None

    try:
        data = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
        return data.get("access_token")
    except (OSError, json.JSONDecodeError):
        return None


def login():
    if not GITHUB_CLIENT_ID:
        raise RuntimeError(
            "GITHUB_CLIENT_ID is missing. "
            "Add it to your .env file."
        )

    response = requests.post(
        DEVICE_CODE_URL,
        data={
            "client_id": GITHUB_CLIENT_ID,
            "scope": "repo"
        },
        headers={
            "Accept": "application/json"
        },
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"]

    print()
    print("GitHub authentication")
    print("=" * 50)
    print()
    print(f"Open this URL:")
    print(f"  {verification_uri}")
    print()
    print(f"Enter this code:")
    print(f"  {user_code}")
    print()
    print("Waiting for GitHub authorization...")
    print()

    interval = data.get("interval", 5)
    expires_in = data.get("expires_in", 900)

    start_time = time.time()

    while time.time() - start_time < expires_in:

        response = requests.post(
            ACCESS_TOKEN_URL,
            data={
                "client_id": GITHUB_CLIENT_ID,
                "device_code": device_code,
                "grant_type":
                    "urn:ietf:params:oauth:grant-type:device_code"
            },
            headers={
                "Accept": "application/json"
            },
            timeout=30
        )

        response.raise_for_status()

        result = response.json()

        if "access_token" in result:
            token = result["access_token"]

            save_token(token)

            print("[OK] GitHub authentication successful.")
            print(f"[OK] Token saved to: {TOKEN_FILE}")

            return token

        error = result.get("error")

        if error == "authorization_pending":
            time.sleep(interval)
            continue

        if error == "slow_down":
            interval += 5
            time.sleep(interval)
            continue

        if error == "expired_token":
            raise RuntimeError(
                "GitHub device code expired. Please run login again."
            )

        if error == "access_denied":
            raise RuntimeError(
                "GitHub authorization was denied."
            )

        raise RuntimeError(
            f"GitHub OAuth error: {error}"
        )

    raise RuntimeError(
        "GitHub authorization timed out."
    )


def get_token():
    token = load_token()

    if token:
        return token

    return login()