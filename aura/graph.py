import time

import requests
from requests_html import HTMLSession
import networkx
from networkx.readwrite.gexf import write_gexf

from . import config

# TODO: add requests-html to requirements

session = HTMLSession()
logger = config.get_logger(__name__)

def get_pypi_author_packages(author):
    resp = session.get(f"https://pypi.org/user/{author}/")
    packages = []

    for pkg in resp.html.find(".package-list .package-snippet"):
        name = pkg.find(".package-snippet__title", first=True).text
        packages.append(name)

    return packages


def get_pypi_dependents(pkg):
    token = config.get_token('librariesio')

    if token is None:
        raise EnvironmentError("You need to configure a token for the Libraries.io API access to use this functionality")

    time.sleep(1)  # FIXME: avoid rate limits
    dependents = []
    resp = requests.get(f"https://libraries.io/api/pypi/{pkg}/dependents?api_key={token}")

    for x in resp.json():
        dependents.append(x['name'])

    return dependents


class AttackVectorGraph:
    def __init__(self):
        self.g = networkx.DiGraph()
        self.processed_cache = set()

    @classmethod
    def pkg_label(cls, package):
        return package

    @classmethod
    def user_label(cls, user):
        return "User " + user

    def user_compromised(self, user):
        a_label = self.user_label(user)
        self.g.add_node(a_label, compromised=True, type="user")
        pkgs = get_pypi_author_packages(user)
        for x in pkgs:
            logger.info(f"Adding user '{user}' pkg compromise '{x}'")
            self.package_compromised(x)
            pkg_label = self.pkg_label(x)
            self.g.add_edge(
                a_label,
                pkg_label,
                label = "is_maintainer",
                compromised = True
            )

    def package_compromised(self, pkg):
        pkg_label = self.pkg_label(pkg)
        self.processed_cache.add(pkg_label)
        self.g.add_node(pkg_label, compromised=True, type="package")
        dependents = get_pypi_dependents(pkg)
        for x in dependents:
            logger.info(f"Adding {pkg} dependent compromise '{x}'")
            x_label = self.pkg_label(x)
            if x_label not in self.processed_cache:
                self.package_compromised(x)
            self.g.add_edge(
                x_label,
                pkg_label,
                label = "depends_on",
                compromised = True
            )

    def save_gexf(self, pth):
        write_gexf(G=self.g, path=pth, prettyprint=True)
