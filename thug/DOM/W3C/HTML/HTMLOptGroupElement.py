#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property


class HTMLOptGroupElement(HTMLElement):
    disabled = bool_property("disabled")
    label    = attr_property("label")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
