#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLLegendElement(HTMLElement):
    accessKey = attr_property("accesskey")
    align     = attr_property("align")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def form(self):
        pass
