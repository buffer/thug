#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLHtmlElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    version         = attr_property("version")

