#!/usr/bin/env python
from __future__ import with_statement

class abstractmethod(object):
    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwds):
        raise NotImplementedError("method %s is abstract." % self.func.func_name)
