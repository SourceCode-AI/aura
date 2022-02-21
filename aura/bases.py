from abc import abstractmethod, ABC
from typing import ClassVar, Union, Set, Any
from inspect import getdoc, getmembers


MISSING = object()


class JSONSerializable(ABC):
    def to_json(self) -> dict:
        return self.to_dict()

    @abstractmethod
    def to_dict(self) -> dict:
        ...


class AbstractAnalyzer(ABC):
    analyzer_description: Union[object, str] = MISSING

    @property
    def description(self) -> str:  # TODO transition info to this method
        if self.analyzer_description is not MISSING:
            return self.analyzer_description
        else:
            return getdoc(self) or "Description N/A"


# TODO: transition NodeAnalyzerV2 to this class
class ASTAnalyzer(AbstractAnalyzer):
    analyzer_id: ClassVar
    # After which AST stage this analyzer should run
    # TODO implement support for this
    stage: str = "final"

    def __init__(self, *args, **kwargs):
        if not self.analyzer_id:
            raise RuntimeError(f"You must define the analyzer_id for `{self.__class__}`!")

        super().__init__(*args, **kwargs)
        self._node_types = None

    @property
    def defined_node_types(self) -> dict[str, any]:
        if self._node_types is None:
            self._node_types = dict()

            for attr, val in getmembers(self):
                if attr.startswith("node_"):
                    self._node_types[attr] = val

        assert self._node_types is not None  # This is to make mypy happy
        return self._node_types

    def _visit_node(self, context):
        yield from []


# TODO: transition raw file analyzers to this class
class RawFileAnalyzer(ABC):
    def __init__(self, analyzer_id: str):
        self.analyzer_id = analyzer_id
        self._func = None

    def __call__(self, func):
        self._func = func

    def run_analyzer(self, *args, **kwargs):
        yield from self._func(*args, **kwargs)
