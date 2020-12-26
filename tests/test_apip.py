import os
import subprocess
import tempfile
import shutil
import venv
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")


def run_in_venv(venv_pth:str, cmd, stdin:bytes=b'', aura_path=None):
    env = os.environ.copy()

    if aura_path is None:
        aura_path = shutil.which('aura')

    # Get the original $PATH value, works on POSIX compliant systems
    pth = subprocess.getoutput('getconf PATH')

    env['VIRTUAL_ENV'] = venv_pth
    env['PYTHONPATH'] = venv_pth
    env['__PYVENV_LAUNCHER__'] = f'{venv_pth}/bin/python'  # Needed for mac
    env['PATH'] = f'{venv_pth}/bin:{pth}'
    env['AURA_PATH'] = aura_path
    env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    env['PIP_REQUIRE_VIRTUALENV'] = '1'
    env["PYTHONWARNINGS"] = "ignore"

    cwd = os.getcwd()
    os.chdir(venv_pth)

    p = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True
    )
    if stdin:
        p.stdin.write(stdin)
    p.stdin.close()
    p.wait()
    os.chdir(cwd)
    return (p.stdout.read().decode(), p.returncode)


@pytest.mark.e2e
def test_apip():
    # Test package taken from pip tests
    # https://github.com/pypa/pip/tree/master/tests/data/packages
    whl = Path(__file__).parent /'files' / 'simplewheel-1.0-py2.py3-none-any.whl'

    venv_dir = tempfile.mkdtemp(suffix="_pytest_aura_apip")
    # print(f'Virtualenv created in {venv_dir}')
    try:
        # Create virtualenv
        venv.create(
            env_dir=venv_dir,
            with_pip=True,
            symlinks=True
        )
        # Install apip
        shutil.copy(
            Path(__file__).parent.parent / 'aura' / 'apip.py',
            f'{venv_dir}/bin/apip'
        )

        assert os.access(f'{venv_dir}/bin/apip', os.X_OK) is True

        stdout, ret = run_in_venv(venv_dir, ['which apip'])
        assert stdout.startswith(venv_dir), stdout

        # Installation should fail/abort
        stdout, ret = run_in_venv(
            venv_dir,
            [f'{venv_dir}/bin/apip install {whl}'],
            # We can't use just "exit 1" here because that's a built-in shell command
            aura_path='python -c "import sys;sys.exit(1)"'
        )
        # print(stdout)
        assert ret > 0, stdout
        stdout, _ = run_in_venv(venv_dir, [f'{venv_dir}/bin/apip freeze'])
        assert not stdout.strip(), stdout

        # Installation should proceed correctly in this case
        stdout, _ = run_in_venv(
            venv_dir,
            [f'{venv_dir}/bin/apip install {whl}'],
            aura_path='python -c "import sys;sys.exit(0)"'
        )
        # print(stdout)

        stdout, _ = run_in_venv(venv_dir, [f'{venv_dir}/bin/apip freeze'])
        # print(stdout)
        assert 'simplewheel' in stdout, stdout
        assert 'Flask' not in stdout, stdout
    finally:
        shutil.rmtree(venv_dir)


if __name__ == '__main__':
    test_apip()
