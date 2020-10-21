import json
from unittest import mock

from aura import cache


def test_mirror_cache(fixtures, simulate_mirror, tmp_path):
    cache_content = list(tmp_path.iterdir())
    assert len(cache_content) == 0

    with mock.patch.object(cache.Cache, 'get_location', return_value=tmp_path) as m:
        assert cache.Cache.get_location() == tmp_path
        out = fixtures.get_cli_output(['scan', '--download-only', 'mirror://wheel', '-f', 'json'])

    parsed_output = json.loads(out.stdout)
    assert len(parsed_output["detections"]) == 0

    cache_content = list(x.name for x in tmp_path.iterdir())
    assert len(cache_content) > 0
    assert "mirror_wheel-0.34.2.tar.gz" in cache_content, cache_content
    assert "mirror_wheel-0.34.2-py2.py3-none-any.whl" in cache_content
