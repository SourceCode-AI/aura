from urllib.parse import urlparse

import requests
import json

from .exceptions import NoSuchRepository


SESSION = requests.Session()
SESSION.headers.update({
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Aura Security"
})


class GitHub:
    def __init__(self, owner, repo_name):
        self.owner = owner
        self.name = repo_name

        self.repo = self.get_repository_data()
        self.contributors = self.get_contributors()

    @classmethod
    def from_url(cls, url: str):
        parsed = urlparse(url)

        if parsed.netloc != "github.com":
            raise NoSuchRepository(url)

        paths = parsed.path.lstrip("/").split("/")
        if len(paths) < 2:
            raise NoSuchRepository(url)

        return cls(owner=paths[0], repo_name=paths[1])

    def get_repository_data(self):
        url = f"https://api.github.com/repos/{self.owner}/{self.name}"

        repo_data = SESSION.get(url)
        if repo_data.status_code == 404:
            raise NoSuchRepository(f"{self.owner}/{self.name}")

        return json.loads(repo_data.text)

    def get_contributors(self):
        url = f"https://api.github.com/repos/{self.owner}/{self.name}/contributors"
        return SESSION.get(url).json()
