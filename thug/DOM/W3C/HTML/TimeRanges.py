#!/usr/bin/env python

from thug.DOM.JSClass import JSClass
from thug.DOM.W3C.Core.DOMException import DOMException


class TimeRanges(JSClass):
    def __init__(self, doc, ranges):
        self.doc = doc
        self.ranges = ranges

    @property
    def length(self):
        return len(self.ranges)

    def start(self, index):
        if index in range(0, len(self.ranges)):
            return self.ranges[0][0] # pragma: no cover

        raise DOMException(DOMException.INDEX_SIZE_ERR)

    def end(self, index):
        if index in range(0, len(self.ranges)):
            return self.ranges[0][1] # pragma: no cover

        raise DOMException(DOMException.INDEX_SIZE_ERR)
