#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import *

class HTMLPreElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    width           = attr_property("width", thug_long)

