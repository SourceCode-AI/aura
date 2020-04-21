import pytest
import responses

from aura import github
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
