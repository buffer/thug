#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .form_property import form_property


class HTMLLegendElement(HTMLElement):
    accessKey = attr_property("accesskey")
    align     = attr_property("align")
    form      = form_property()

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
