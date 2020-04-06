from collections import defaultdict


class Frame:
    __slots__ = ("locals", "previous")

    def __init__(self):
        self.locals = {}
        self.previous = None  # type: Frame

    def _lookup(self, key):
        if key in self.locals:
            return (self, self.locals[key])
        elif self.previous is not None:
            return self.previous._lookup(key)
        else:
            raise KeyError("No such variable in stack frames: '{}'".format(key))

    def __getitem__(self, key):
        return self._lookup(key)[1]

    def __setitem__(self, key, value):
        if key in self.locals:
            self.locals[key] = value

        try:
            loc, _ = self.previous[key]
            loc[key] = value
        except (TypeError, KeyError):
            self.locals[key] = value

    def copy(self):  # type: Frame
        l = self.locals.copy()
        frame_copy = Frame()
        frame_copy.locals = l.copy()
        return frame_copy

    @property
    def variables(self):
        l = list(self.locals.keys())

        if self.previous:
            l.extend(self.previous.variables)
        return l


class Stack:
    __slots__ = ("bottom", "frame")

    def __init__(self):
        self.bottom = Frame()
        self.frame = self.bottom

    def __contains__(self, item):
        try:
            _ = self[item]
            return True
        except KeyError:
            return False

    def __getitem__(self, item):
        return self.frame[item]

    def __setitem__(self, key, value):
        self.frame[key] = value

    def push(self):
        new_frame = Frame()
        new_frame.previous = self.frame
        self.frame = new_frame

    def pop(self):
        top = self.frame
        if top.previous is None:
            raise ValueError("Can't pop top frame")

        self.frame = top.previous
        del top

    def copy(self):
        frames = []
        frame = self.frame
        while frame:
            new_frame = frame.copy()
            if frames:
                new_frame.previous = frames[-1]
            frames.append(new_frame)
            frame = frame.previous

        new_stack = self.__class__()
        new_stack.frame = frames[-1]
        new_stack.bottom = frames[0]
        return new_stack


class CallGraph:
    __slots__ = ("references", "definitions", "object_access")

    def __init__(self):
        self.definitions = dict()
        self.references = defaultdict(set)
        self.object_access = defaultdict(list)

    def __setitem__(self, key, value):
        self.references[key].add(value)

    def __getitem__(self, key):
        return self.references[key]

    def __contains__(self, item):
        return item in self.references

    def pprint(self):
        import pprint

        print("Callers:")
        pprint.pprint({k: [x.json for x in v] for k, v in self.references.items()})
        print("Definitions:")
        pprint.pprint({k: v.json for k, v in self.definitions.items()})
