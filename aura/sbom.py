"""
Module functionality related to SBOMs - Software bill of materials
"""

import uuid
from typing import Optional, Dict, List, Any, Set

from . import config
from . import package
from .json_proxy import loads as load_json


LICENSE_CACHE: Optional[Dict[str, str]] = None


class Sbom:
    def __init__(self):
        self._id = str(uuid.uuid4())
        self.packages: List[package.PypiPackage] = []

    def add_package(self, pkg: package.PypiPackage):
        self.packages.append(pkg)

    def generate(self) -> Dict[str, Any]:
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": f"urn:uuid:{self._id}",
            "version": 1,
            "components": []
        }

        for pkg in self.packages:
            data["components"].append(get_component(pkg))

        return data



def load_licenses() -> Dict[str, str]:
    """
    Helper to load the license information from the filesystem and caching the data

    :return: Database of known licenses
    """
    global LICENSE_CACHE

    if LICENSE_CACHE is None:
        location = config.CFG["sbom"]["licenses"]
        LICENSE_CACHE = load_json(config.get_file_content(location))

    return LICENSE_CACHE


def get_license_identifier(data: str) -> Optional[str]:
    """
    Lookup an SPDX license from the given data such as package classifiers
    List of valid SPDX license identifiers can be found at: https://spdx.org/licenses/

    :param data: string payload that is used to lookup the license information
    :return: SPDX license identifier if matching license has been found
    """
    licenses = load_licenses()
    data = data.strip()

    if data in licenses:  # Look if the payload is in a license database
        return licenses[data]

    data = data.replace(" ", "-")

    if data in licenses.values():  # Check if payload is already a valid SPDX identifier
        return data
    else:
        return None


def get_package_licenses(pkg: package.PypiPackage) -> Set[str]:
    """
    Attempt to detect an SPDX license identifier for the given PyPI package

    :param pkg: PyPI package to scan the license for
    :return: SPDX license identifier if license is detected
    """
    licenses = set()

    if info_license := pkg.info["info"].get("license"):
        if license_ := get_license_identifier(info_license):
            licenses.add(license_)

    for classifier in pkg.info["info"].get("classifiers", []):
        if classifier.startswith("License"):
            if license_ := get_license_identifier(classifier):
                licenses.add(license_)

    return licenses


def get_package_purl(pkg: package.PypiPackage) -> str:
    """
    Create a package url (purl) specifier from a given PyPI package

    :param pkg: pypi package
    :return: generated purl
    """
    purl = f"pkg:pypi/{pkg.name}"

    if version := pkg.version:
        purl += "@" + version

    return purl


def get_component(pkg: package.PypiPackage) -> Dict[str, Any]:
    data = {
        "type": "library",
        "name": pkg.name,
        "purl": get_package_purl(pkg),
        "description": pkg.info["info"]["description"]
    }

    version = pkg.version
    hashes = []

    if version:
        data["version"] = version

        for release in pkg.info["releases"].get(version, []):
            hashes.append({
                "alg": "MD5",
                "content":  release["digests"]["md5"]
            })
            hashes.append({
                "alg": "SHA-256",
                "content": release["digests"]["sha256"]
            })

    if hashes:
        data["hashes"] = hashes

    licenses = []

    for l in get_package_licenses(pkg):
        licenses.append({
            "license": {
                "id": l
            }
        })

    if licenses:
        data["licenses"] = licenses

    if (author:=pkg.info["info"].get("author_email")):
        data["author"] = author

    if (publisher:=pkg.info["info"].get("author")):
        data["publisher"] = publisher

    return data


def is_enabled() -> bool:
    return config.CFG["sbom"].get("enabled", False)
