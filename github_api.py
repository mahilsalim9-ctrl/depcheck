import base64

import requests

from github_oauth import get_token


GITHUB_API = "https://api.github.com"


class GitHubAPI:

    def __init__(self):
        self.token = get_token()

        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    def request(self, method, endpoint, **kwargs):

        url = f"{GITHUB_API}{endpoint}"

        response = requests.request(
            method,
            url,
            headers=self.headers,
            timeout=30,
            **kwargs
        )

        if response.status_code == 401:
            raise RuntimeError(
                "GitHub authentication failed or token expired."
            )

        if response.status_code == 403:
            raise RuntimeError(
                "GitHub access denied. Check OAuth permissions."
            )

        if response.status_code == 404:
            raise RuntimeError(
                "GitHub repository or file not found."
            )

        response.raise_for_status()

        return response.json()

    def get_user(self):

        return self.request(
            "GET",
            "/user"
        )

    def list_repositories(self):

        repositories = []

        page = 1

        while True:

            data = self.request(
                "GET",
                "/user/repos",
                params={
                    "per_page": 100,
                    "page": page,
                    "sort": "updated"
                }
            )

            if not data:
                break

            repositories.extend(data)

            if len(data) < 100:
                break

            page += 1

        return repositories

    def get_repository(self, owner, repo):

        return self.request(
            "GET",
            f"/repos/{owner}/{repo}"
        )

    def get_contents(self, owner, repo, path=""):

        return self.request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{path}"
        )

    def get_file(self, owner, repo, path):

        data = self.get_contents(
            owner,
            repo,
            path
        )

        if isinstance(data, list):
            raise RuntimeError(
                f"{path} is a directory, not a file."
            )

        content = data.get("content", "")

        if data.get("encoding") == "base64":
            return base64.b64decode(content).decode(
                "utf-8",
                errors="replace"
            )

        return content