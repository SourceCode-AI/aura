
class Frame:
    __slots__ = ('locals', 'globals', 'previous')
    def __init__(self):
        self.locals = {}
        self.globals = None
        self.previous = None  # type: Frame

    def _lookup(self, key):
        if key in self.locals:
            return (self, self.locals[key])
        elif self.previous is not None:
            return self.previous._lookup(key)
        elif self.globals:
            return (self, self.globals[key])
        else:
            raise KeyError("No such variable in stack frames: '{}'".format(key))

    def __getitem__(self, key):
        return self._lookup(key)[1]

    def __setitem__(self, key, value):
        if self.globals and key in self.globals:
            self.globals[key] = value
        elif key in self.locals:
            self.locals[key] = value

        try:
            loc, _ = self.previous[key]
            loc[key] = value
        except (TypeError, KeyError):
            self.locals[key] = value

    @property
    def variables(self):
        l = list(self.locals.keys())
        if self.globals:
            l.extend(self.globals.keys())

        if self.previous:
            l.extend(self.previous.variables)
        return l

class Stack:
    __slots__ = ('bottom', 'frame')

    def __init__(self):
        self.bottom = Frame()
        self.bottom.globals = {}
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
