#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLIsIndexElement(HTMLElement):
    form   = None
    prompt = attr_property("prompt")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
