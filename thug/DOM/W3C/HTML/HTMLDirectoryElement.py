#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .bool_property import bool_property


class HTMLDirectoryElement(HTMLElement):
    compact = bool_property("compact")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
