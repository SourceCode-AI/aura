from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse
from urllib.error import HTTPError
from typing import Optional, Union

import requests

from . import config
from .cache import URLCache
from .utils import remaining_time
from .exceptions import NoSuchRepository, RateLimitError


logger = logging.getLogger(__name__)
SESSION = requests.Session()
SESSION.headers.update({
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Aura Security"
})

if API_TOKEN:=config.get_token("github_api"):
    SESSION.headers["Authorization"] = f"token {API_TOKEN}"


class GitHub:
    x_api_remaining: Optional[float] = None
    x_api_reset: Optional[float] = None

    def __init__(self, owner: str, repo_name: str):
        self.owner: str = owner
        self.name: str = repo_name
        self.repo = self.get_repository_data()
        self.contributors = self.get_contributors()

    @classmethod
    def from_url(cls, url: str) -> GitHub:
        parsed = urlparse(url)

        if parsed.netloc != "github.com":
            raise NoSuchRepository(url)

        paths = parsed.path.lstrip("/").split("/")
        if len(paths) < 2:
            raise NoSuchRepository(url)

        return cls(owner=paths[0], repo_name=paths[1])

    @classmethod
    def time_to_reset(cls) -> float:
        if cls.x_api_reset:
            return remaining_time(cls.x_api_reset)
        else:
            return 0.0

    def __get_json(self, url: str) -> Union[dict, list]:
        payload = URLCache.proxy(url=url, tags=["github_api"], session=SESSION)
        return json.loads(payload)

    def get_repository_data(self) -> dict:
        url = f"https://api.github.com/repos/{self.owner}/{self.name}"

        try:
            return self.__get_json(url)
        except HTTPError as exc:
            if exc.code == 404:
                raise NoSuchRepository(f"{self.owner}/{self.name}") from exc
            else:
                raise

    def get_contributors(self) -> list:
        url = f"https://api.github.com/repos/{self.owner}/{self.name}/contributors"
        return self.__get_json(url=url)


class GitHubPrefetcher:
    STOP = object()

    def __init__(self):
        self.queue = asyncio.Queue()
        # Safety margin for API requests to leave in the rate limit
        # There is usually more than one request required to load the github data
        self.safety_buffer = 10

    @property
    def wait_time(self) -> float:
        """
        Calculate number of seconds to wait before prefetching the next github repo
        """
        if GitHub.x_api_remaining is None:
            return 0.0

        reset_time = GitHub.time_to_reset()

        if GitHub.x_api_remaining - self.safety_buffer <= 0:
            return reset_time

        return (reset_time / (GitHub.x_api_remaining-self.safety_buffer))

    async def process(self):
        while True:
            api_wait_time = self.wait_time
            if self.wait_time > 3:
                logger.info(f"Rate limit reached, waiting for {api_wait_time}s")

            await asyncio.sleep(api_wait_time)
            url: Optional[str] = await self.queue.get()
            if not url:
                continue
            elif url == GitHubPrefetcher.STOP:
                break

            # Fetch the github repo data which will store it in a cache
            try:
                logger.info(f"Attempting to prefetch repository data for: `{url}`")
                _ = GitHub.from_url(url)
            except NoSuchRepository:
                logger.warning(f"GitHub repository does not exists or access was denied: `{url}`")
            except RateLimitError:
                await self.queue.put(url)


def update_rate_limits(response: requests.Response, **kwargs):
    remaining = response.headers.get("X-Ratelimit-Remaining")
    reset = response.headers.get("X-Ratelimit-Reset")

    if remaining is None or reset is None:
        logger.warning("Could not find api rate limit headers in the response")
        return

    GitHub.x_api_reset = float(reset)
    GitHub.x_api_remaining = float(remaining)

    if response.status_code == 403:
        raise RateLimitError("GitHub API rate limit exceeded")
    response.raise_for_status()


SESSION.hooks["response"] = update_rate_limits
