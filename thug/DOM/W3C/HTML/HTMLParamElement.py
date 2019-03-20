#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLParamElement(HTMLElement):
    name      = attr_property("name")
    type      = attr_property("type")
    value     = attr_property("value")
    valueType = attr_property("valuetype")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
