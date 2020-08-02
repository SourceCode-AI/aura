import networkx
from networkx.readwrite.gexf import write_gexf

from . import config
from . import package


logger = config.get_logger(__name__)


class AttackVectorGraph:
    def __init__(self):
        self.g = networkx.DiGraph()
        self.processed_cache = set()

    @classmethod
    def pkg_label(cls, package):
        return package

    @classmethod
    def user_label(cls, user):
        return f"User {user}"

    def user_compromised(self, user):
        a_label = self.user_label(user)
        self.g.add_node(a_label, compromised=True, type="user")
        pkgs = [x[1] for x in package.get_packages_for_author(user)]
        for x in pkgs:
            logger.info(f"Adding user '{user}' pkg compromise '{x}'")
            self.package_compromised(x)
            pkg_label = self.pkg_label(x)
            self.g.add_edge(a_label, pkg_label, label="is_maintainer", compromised=True)

    def package_compromised(self, pkg):
        pkg_label = self.pkg_label(pkg)
        self.processed_cache.add(pkg_label)
        self.g.add_node(pkg_label, compromised=True, type="package")
        for x in package.get_reverse_dependencies(pkg):
            logger.info(f"Adding {pkg} dependent compromise '{x}'")
            x_label = self.pkg_label(x)
            if x_label not in self.processed_cache:
                self.package_compromised(x)
            self.g.add_edge(x_label, pkg_label, label="depends_on", compromised=True)

    def save_gexf(self, pth):
        write_gexf(G=self.g, path=pth, prettyprint=True)
