#!/usr/bin/env python
#-*- coding: utf-8 -*-
"""
PIP wrapper for aura security project
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
import subprocess

import pip
from pip._internal import main as pip_main
from pip._internal.req import InstallRequirement

# Polyfill for compatibility (Py2k & Py3k) to retrieve user input
try:
    text_input = raw_input  # pylint: disable
except NameError:
    text_input = input



SUPPORTED_PIP_VERSIONS = ('19.*', '10.*')
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
        req # type: InstallRequirement
    ):
    chain = []
    while req:
        chain.append(req.name)
        req = req.comes_from
    return chain[::-1]


def ask_user(label):
    """
    Helper function that asks user for a confirmation
    This is used for interactively aborting installation
    """
    answer = text_input("{} [y/N]:".format(label)).strip().lower()

    if answer in ('y', 'yes'):
        return True
    else:
        return False


def check_package(pkg):
    """
    Check a given package by calling aura security framework

    :param pkg:
    :return:
    """
    import pprint
    pprint.pprint(pkg)

    payload = json.dumps(pkg)

    subprocess.run(
        [os.environ['AURA_PATH'], 'check_requirement'],
        # check=True,
        input=payload,
        text=True
    )

    if not ask_user("Would you like to proceed with installation?"):
        raise EnvironmentError("Installation aborted by user")

    raise EnvironmentError("Install")

def mp_install_requirement(
        self,  # type: InstallRequirement
        *args, **kwargs
    ):
    """
    Monkey patch for the InstallRequirement.install method
    It collects the package information and sends it to aura for security audit
    User then has a choice to proceed or abort the installation process based on audit results
    """
    subprocess.call(['tree', self.setup_py_dir])

    data = {
        'format': '0.1',
        'cmd': sys.argv,
        'name': self.name,
        'path': self.setup_py_dir,
        'wheel': self.is_wheel,
        'is_pinned': self.is_pinned,
        'editable': self.editable,
        'update': self.update,
        'url': self.req.url,
        'dependency_chain': get_dependency_chain(self),
    }

    check_package(data)


def monkey_patch():
    InstallRequirement._orig_install = InstallRequirement.install
    InstallRequirement.install = mp_install_requirement


def main():
    if not check_version():
        logger.error("Unsupported pip version: '{}'".format(pip.__version__))
        logger.error("Use one of the supported versions: {}".format(', '.join(SUPPORTED_PIP_VERSIONS)))

        if not ask_user("Do you really want to continue?"):
            sys.exit(1)

    if not os.environ.get('AURA_PATH'):
        logger.error("You need to set AURA_PATH environment variable that points to the AURA framework executable")

    logger.debug("Monkey patching pip...")
    monkey_patch()
    sys.exit(pip_main())


if __name__ == '__main__':
    main()
