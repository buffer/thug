#!/usr/bin/env python

import sys


class abstractmethod(object):
    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwds):
        func_name = self.func.__name__ if sys.version_info.major >= 3 else self.func.func_name
        raise NotImplementedError("method {} is abstract".format(func_name))
