from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Optional

from . import find_imports_inject
from .. import python_executor
from .. import utils


class TopologySort:
    def __init__(self):
        self.graph = defaultdict(set)
        self.all_locations = set()

    def add_node(self, node):
        self.all_locations.add(node)

    def add_edge(self, node, edges):
        for e in edges:
            if e == node:
                continue
            elif e not in self.all_locations:
                continue

            self.graph[node].add(e)

    def sort(self) -> List[Path]:
        topology = []
        g = dict(self.graph)

        while g:
            best: Optional[Tuple[int, Path]] = None
            keys = set(g.keys())

            for node, edges in g.items():
                rank = len(keys & edges)
                if best is None or rank < best[0]:
                    best = (rank, node)

            topology.append(best[1])
            g.pop(best[1])

        return topology


def native_find_imports(command):
    src_path = command[-1]
    with open(src_path, "r") as fd:
        co = compile(fd.read() + "\n", src_path, "exec")

    return list(find_imports_inject.find_imports(co))


def get_imports(py_src, metadata=None) -> List:
    importer_path = Path(__file__).parent / "find_imports_inject.py"
    cmd = [utils.normalize_path(importer_path), utils.normalize_path(py_src)]

    return python_executor.run_with_interpreters(
        command=cmd,
        metadata=metadata,
        native_callback=native_find_imports
    )


# TODO: add support for other "pythonic" files, see modulefinder (pyc, dynlib etc.)
def find_imports(py_src: Path, metadata=None):
    """
    Construct a dependency matrix of import files
    """
    dependencies = set()
    unknown = set()

    imports = get_imports(py_src, metadata=metadata)
    if not imports:
        return

    for level, pkg, name in imports:
        if level == 0 or pkg is None:
            # TODO: add support for absolute imports
            continue

        dependency = py_src.absolute()

        for i in range(level):
            dependency = dependency.parent

        if name:
            for pkg_name in name.split("."):
                dependency /= pkg_name

        for var in pkg:
            d = dependency / (var + ".py")
            if not d.exists():
                continue
            dependencies.add(d)
        else:
            try:
                py_ext = dependency.with_suffix(".py")
            except ValueError:
                continue

            init = dependency / "__init__.py"
            if py_ext.exists():
                dependencies.add(py_ext)
            elif init.exists():
                dependencies.add(init)
            else:
                unknown.add(dependency)

    return {"dependencies": dependencies, "unknown": unknown}


if __name__ == "__main__":
    import pprint, sys

    dep = find_imports(Path(sys.argv[1]))
    pprint.pprint(dep)
