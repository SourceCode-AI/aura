from click import style

from dataclasses import dataclass, field
from typing import Any, List, Iterable, Optional


EMPTY = object()


@dataclass()
class Column:
    value: Any
    metadata: dict = field(default_factory=dict)

    def __str__(self):
        if type(self.value) == str:
            return self.value
        else:
            return repr(self.value)

    def __len__(self):
        return len(str(self))

    @property
    def style(self) -> dict:
        if "style" in self.metadata:
            return self.metadata["style"]

        s = {}
        if type(self.value) == bool:
            s = {"fg": ("green" if self.value else "red")}

        if self.value == 0:
            s = {"fg": "red"}

        return s

    @property
    def pretty(self) -> str:
        return style(str(self), **self.style)

    def asdict(self) -> dict:
        data = {
            "value": self.value
        }
        if self.metadata:
            data["metadata"] = self.metadata

        return data


@dataclass()
class Table:
    rows: List[Iterable[Column]] = field(default_factory=list)
    n_cols: Optional[int] = None
    # Used to calculate the maximum column width/padding for text based outputs
    col_len: Optional[List[int]] = None
    metadata: dict = field(default_factory=dict)

    def __iadd__(self, other):
        row = []

        if self.n_cols is None:
            self.n_cols = len(other)
            self.col_len = [0]*self.n_cols
        else:
            # Verify that each row has the same number of columns
            assert len(other) == self.n_cols

        for idx, c in enumerate(other):
            # Convert the item to Column object if needed
            if not isinstance(c, Column):
                column = Column(c)
            else:
                column = c

            # Update the maximum width of a column
            if self.col_len[idx] < len(column):
                self.col_len[idx] = len(column)

            row.append(column)

        self.rows.append(tuple(row))

        return self

    def __iter__(self):
        yield from self.rows

    @property
    def width(self) -> int:
        title_width = len(self.metadata.get("title", ""))
        return max(sum(self.col_len)+3, title_width)

    def asdict(self) -> dict:
        d = {"rows": [
            [c.asdict() for c in row] for row in self.rows
        ]}
        if self.metadata:
            d["metadata"] = self.metadata

        return d

    def pprint(self, preport=None):
        from .text import PrettyReport

        if preport is None:
            preport = PrettyReport()

        preport.print_tables(self, self)

        preport.print_top_separator()

        if self.metadata.get("title"):
            preport.print_heading(self.metadata["title"])

        for row in self:
            cols = []
            for idx, col in enumerate(row):
                text = preport._align_text(style(str(col), **col.style), width=self.col_len[idx])
                cols.append(text)

            preport.align(" \u2502 ".join(cols))

        preport.print_bottom_separator()

