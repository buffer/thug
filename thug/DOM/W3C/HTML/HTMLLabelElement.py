#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLLabelElement(HTMLElement):
    accessKey = attr_property("accesskey")
    htmlFor   = attr_property("for")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def form(self):
        pass
