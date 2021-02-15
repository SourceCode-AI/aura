import json
import pytest
import responses

from aura import github
from aura import cache
from aura import exceptions


@responses.activate
def test_github_api(mock_github):
    mock_github(responses)
    url = "https://github.com/psf/requests"
    g = github.GitHub.from_url(url)

    assert g.owner == "psf"
    assert g.name == "requests"
    assert g.repo["html_url"] == url
    assert len(g.contributors) > 0


@pytest.mark.parametrize(
    "url",
    (
        "https://google.com/",
        "https://github.com/",
        "https://github.com/RootLUG",
    )
)
@responses.activate
def test_invalid_github_repos(url, mock_github):
    mock_github(responses)
    with pytest.raises(exceptions.NoSuchRepository):
        github.GitHub.from_url(url)


@responses.activate
def test_github_cache(mock_github, mock_cache):
    mock_github(responses)

    _ = github.GitHub.from_url("https://github.com/psf/requests")

    url1_cached = cache.URLCache(url="https://api.github.com/repos/psf/requests")
    assert url1_cached.is_valid is True
    assert type(json.loads(url1_cached.fetch())) == dict

    url2_cached = cache.URLCache(url="https://api.github.com/repos/psf/requests/contributors")
    assert url2_cached.is_valid
    assert type(json.loads(url2_cached.fetch())) == list


@responses.activate
def test_github_rate_limit_reached():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/psf/requests",
        headers={
            "X-Ratelimit-Remaining": "0",
            "X-Ratelimit-Reset": "666"
        },
        status=403
    )

    assert github.GitHub.x_api_reset is None
    assert github.GitHub.x_api_remaining is None

    with pytest.raises(exceptions.RateLimitError):
        _ = github.GitHub.from_url("https://github.com/psf/requests")

    assert github.GitHub.x_api_reset == 666
    assert github.GitHub.x_api_remaining == 0
