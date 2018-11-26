#!/usr/bin/env python

from setuptools import setup

with open("README.md", "r") as fd:
    long_description = fd.read().strip()


with open("requirements.txt", "r") as fd:
    reqs = fd.read().splitlines()


setup(
    name='aura',
    version='0.1a1',
    description='Security aura for packages',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Martin Carnogursky',
    author_email='xcarnog@fi.muni.cz',
    url='https://github.com/RootLUG/aura',
    packages=['aura'],
    install_requires = reqs,
    entrypoints = {
        'console_scripts': ['aura=aura.cli:main']
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ]
)
