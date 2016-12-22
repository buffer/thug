#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLMetaElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    content         = attr_property("content")
    httpEquiv       = attr_property("http-equiv")
    name            = attr_property("name", default = '')
    scheme          = attr_property("scheme")
