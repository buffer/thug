#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

class HTMLModElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    cite            = attr_property("cite")
    dateTime        = attr_property("datetime")

