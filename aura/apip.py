#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PIP wrapper for aura security project
It hijacks the pip install process via monkeypatching and when forwards data to the aura framework for analysis
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import sys
import fnmatch
import logging
import json
import shlex
import subprocess
import shutil


import pip
try:
    from pip._internal.cli.main import main as pip_main
except ImportError:
    from pip._internal import main as pip_main

from pip._internal.req import InstallRequirement

# Polyfill for compatibility (Py2k & Py3k) to retrieve user input
try:
    text_input = raw_input  # pylint: disable
except NameError:
    text_input = input


SUPPORTED_PIP_VERSIONS = ("19.*", "10.*", "20.*", "18.*", "21.*")
AURA_PATH = None
logger = logging.getLogger("apip")


def check_version():
    # type: (...) -> bool
    """
    Check if the currently installed PIP version is supported
    """
    for x in SUPPORTED_PIP_VERSIONS:
        if fnmatch.fnmatch(pip.__version__, x):
            return True
    return False


def get_dependency_chain(
    req,  # type: InstallRequirement
):
    chain = []
    while req:
        chain.append(req.name)
        req = req.comes_from
    return chain[::-1]


def check_package(pkg):
    """
    Check a given package by calling aura security framework

    :param pkg:
    :return:
    """
    import pprint

    pprint.pprint(pkg)

    print("\n*** Installation interrupted by apip ***")

    payload = json.dumps(pkg)

    p = subprocess.Popen(
        shlex.split(AURA_PATH) + ["check_requirement"],
        universal_newlines=True,
        stdin=subprocess.PIPE
    )
    p.communicate(payload)
    p.stdin.close()
    p.wait()

    if p.returncode > 0:
        raise EnvironmentError("Installation aborted")


def mp_install_requirement(
    self,  # type: InstallRequirement
    *args,
    **kwargs
):
    """
    Monkey patch for the InstallRequirement.install method
    It collects the package information and sends it to aura for security audit
    User then has a choice to proceed or abort the installation process based on audit results
    """
    data = {
        "format": "0.1",
        "cmd": sys.argv,
        "name": self.name,
        "path": self.source_dir or self.local_file_path,
        "wheel": self.is_wheel,
        "is_pinned": self.is_pinned,
        "editable": self.editable,
        "update": getattr(self, "update", False),
        "hash": self.link.hash,
        "filename": self.link.filename,
        "url": self.link.url,
        "dependency_chain": get_dependency_chain(self),
    }
    check_package(data)
    InstallRequirement._orig_install(self, *args, **kwargs)


def monkey_patch():
    InstallRequirement._orig_install = InstallRequirement.install
    InstallRequirement.install = mp_install_requirement


def main():
    global AURA_PATH

    if not check_version():
        logger.warning("Unsupported pip version: '{}'".format(pip.__version__))
        logger.warning(
            "Use one of the supported versions: {}".format(
                ", ".join(SUPPORTED_PIP_VERSIONS)
            )
        )

    if "AURA_PATH" in os.environ:
        AURA_PATH = os.environ["AURA_PATH"]
    elif hasattr(shutil, "which"):
        AURA_PATH = shutil.which("aura")

    if AURA_PATH is None:
        logger.error(
            "You need to set AURA_PATH environment variable that points to the AURA framework executable"
        )

    logger.debug("Monkey patching pip...")
    monkey_patch()
    if callable(pip_main):
        ret_code = pip_main()
    else:
        ret_code = pip_main.main()

    sys.exit(ret_code)


if __name__ == "__main__":
    main()
