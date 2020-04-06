#!/usr/bin/env python
"""
This is a a slightly modified redos detection from DLint:
https://github.com/dlint-py/dlint/blob/master/dlint/redos/detect.py
"""
import sre_constants
import sre_parse

import collections
import itertools
import sys

CR = collections.namedtuple('CR', ['cr_min', 'cr_max'])

CATEGORY_TO_RANGE = {
    sre_constants.CATEGORY_DIGIT: [(48, 57)],
    sre_constants.CATEGORY_NOT_DIGIT: [(0, 47), (58, sys.maxunicode)],
    sre_constants.CATEGORY_SPACE: [(9, 13), (32, 32)],
    sre_constants.CATEGORY_NOT_SPACE: [(0, 8), (14, 31), (33, sys.maxunicode)],
    sre_constants.CATEGORY_WORD: [(48, 57), (65, 90), (95, 95), (97, 122)],
    sre_constants.CATEGORY_NOT_WORD: [(0, 47), (58, 64), (91, 94), (96, 96), (123, sys.maxunicode)],
}


class OpNode(object):
    def __init__(self, op, args):
        self.op = op
        self.args = args
        self.children = []

    def __str__(self, level=0):
        result = (
            "  " * level
            + "{}: {}".format(self.op, self.args)
            + "\n"
        )

        for child in self.children:
            result += child.__str__(level + 1)

        return result

    def __repr__(self):
        return "<{} - op={} args={}>".format(
            self.__class__.__name__,
            self.op,
            self.args
        )


def build_op_tree(node, subpattern):
    for op, av in subpattern.data:
        args = []
        subpatterns = []

        if op is sre_constants.BRANCH:
            for a in av[1]:
                subpatterns.append(a)
        elif op is sre_constants.GROUPREF_EXISTS:
            condgroup, item_yes, item_no = av
            subpatterns.append(item_yes)
            if item_no:
                subpatterns.append(item_no)
        elif isinstance(av, (tuple, list)):
            for a in av:
                if isinstance(a, sre_parse.SubPattern):
                    subpatterns.append(a)
                else:
                    args.append(a)
        else:
            args.append(av)

        new_node = OpNode(op, tuple(args))
        for sp in subpatterns:
            build_op_tree(new_node, sp)

        node.children.append(new_node)


class CharacterRange(object):

    def __init__(self, character_ranges, negate=False):
        self.character_ranges = character_ranges
        self.negate = negate

    @classmethod
    def from_any(cls, _any):
        """E.g. '.'"""
        return cls([CR(cr_min=0, cr_max=sys.maxunicode)])

    @classmethod
    def from_literal(cls, literal):
        """E.g. 'a'"""
        return cls([CR(cr_min=literal[0], cr_max=literal[0])])

    @classmethod
    def from_not_literal(cls, not_literal):
        """E.g. '[^a]'"""
        return cls([CR(cr_min=not_literal[0], cr_max=not_literal[0])], negate=True)

    @staticmethod
    def _parse_in_nodes(nodes):
        results = []
        for node_type, args in nodes:
            if node_type is sre_constants.LITERAL:
                results.append(CR(cr_min=args, cr_max=args))
            elif node_type is sre_constants.RANGE:
                results.append(CR(cr_min=args[0], cr_max=args[1]))
            elif node_type is sre_constants.CATEGORY:
                for c, r in CATEGORY_TO_RANGE.items():
                    if args is c:
                        results.extend(
                            CR(cr_min=r_min, cr_max=r_max)
                            for r_min, r_max in r
                        )

        return results

    @classmethod
    def from_in(cls, _in):
        """E.g. '[abcA-Z]'"""
        character_ranges = cls._parse_in_nodes(_in)

        return cls(character_ranges)

    @classmethod
    def from_not_in(cls, not_in):
        """E.g. '[^abcA-Z]'"""
        character_ranges = cls._parse_in_nodes(not_in[1:])  # Avoid initial NEGATE

        return cls(character_ranges, negate=True)

    @classmethod
    def from_op_node(cls, node):
        if node.op is sre_constants.ANY:
            return cls.from_any(node.args)
        elif node.op is sre_constants.LITERAL:
            return cls.from_literal(node.args)
        elif node.op is sre_constants.NOT_LITERAL:
            return cls.from_not_literal(node.args)
        elif (node.op is sre_constants.IN
                and node.args
                and node.args[0] == (sre_constants.NEGATE, None)):
            return cls.from_not_in(node.args)
        elif node.op is sre_constants.IN:
            return cls.from_in(node.args)

        # Unsupported OpNode
        return None

    def overlap(self, other_character_range):
        if self.negate and other_character_range.negate:
            # Unless the sets are disjoint and cover the entire character
            # space they will have overlap - let's punt on the logic and
            # assume this is true
            return True
        elif self.negate:
            character_set = {
                i
                for cr in self.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            other_character_set = {
                i
                for cr in other_character_range.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            return bool(other_character_set - character_set)
        elif other_character_range.negate:
            character_set = {
                i
                for cr in self.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            other_character_set = {
                i
                for cr in other_character_range.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            return bool(character_set - other_character_set)

        return any(
            cr1.cr_min <= cr2.cr_min <= cr1.cr_max
            or cr1.cr_min <= cr2.cr_max <= cr1.cr_max
            for cr1, cr2 in itertools.product(
                self.character_ranges,
                other_character_range.character_ranges
            )
        )

    def __repr__(self):
        return "<{} - negate={} ranges={}>".format(
            self.__class__.__name__,
            self.negate,
            ", ".join(str((cr.cr_min, cr.cr_max)) for cr in self.character_ranges)
        )


def large_repeat(node):
    repeat_min, repeat_max = node.args

    # Repetition sizes that cause catastrophic backtracking depend on many
    # factors including subject length, machine hardware, and the repetition
    # size itself. This value was mostly arbitrarily chosen after running a
    # few basic catastrophic cases. We may consider making it configurable
    # in the future.
    large_max = 10

    return (
        repeat_max is sre_constants.MAXREPEAT  # e.g. '{min,}', '+', '*'
        or repeat_max >= large_max
    )


def max_nested_quantifiers(node):
    if not node.children:
        return 0

    child_max = max(
        max_nested_quantifiers(child)
        for child in node.children
    )
    is_large_repeat = int(
        node.op in sre_parse._REPEATCODES
        and large_repeat(node)
    )

    return is_large_repeat + child_max


def inclusive_alternation_branch(branch_node):
    character_ranges = (
        CharacterRange.from_op_node(node)
        for node in branch_node.children
    )
    return any(
        cr1.overlap(cr2)
        for cr1, cr2 in itertools.combinations(filter(None, character_ranges), 2)
    )


def mutually_inclusive_alternation_helper(node, nested_quantifier):
    if not node.children:
        return False

    nested_quantifier = (
        nested_quantifier
        or (node.op in sre_parse._REPEATCODES and large_repeat(node))
    )

    inclusive_alternation = False
    if node.op is sre_constants.BRANCH:
        inclusive_alternation = inclusive_alternation_branch(node)

    return any(
        (nested_quantifier and inclusive_alternation)
        or mutually_inclusive_alternation_helper(child, nested_quantifier)
        for child in node.children
    )


def mutually_inclusive_alternation(node):
    return mutually_inclusive_alternation_helper(node, False)


def catastrophic(pattern):
    try:
        subpattern = sre_parse.parse(pattern)
    except sre_constants.error:
        return False

    root = OpNode(None, ())

    build_op_tree(root, subpattern)
    nested_quantifiers = max_nested_quantifiers(root) > 1
    alternation = mutually_inclusive_alternation(root)

    return any([
        nested_quantifiers,
        alternation
    ])


def dump(pattern):
    try:
        subpattern = sre_parse.parse(pattern)
    except sre_constants.error as e:
        print("Malformed expression: {}".format(str(e)))
    else:
        subpattern.dump()


def dump_tree(pattern):
    try:
        subpattern = sre_parse.parse(pattern)
    except sre_constants.error as e:
        print("Malformed expression: {}".format(str(e)))
    else:
        root = OpNode(None, ())
        build_op_tree(root, subpattern)
        print(root)
