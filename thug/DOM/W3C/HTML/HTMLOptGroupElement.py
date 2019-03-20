#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLOptGroupElement(HTMLElement):
    disabled = attr_property("disabled", bool)
    label    = attr_property("label")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
