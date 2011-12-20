#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLFormElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def elements(self):
        raise NotImplementedError()

    @property
    def length(self):
        raise NotImplementedError()

    name            = attr_property("name")
    acceptCharset   = attr_property("accept-charset", default = "UNKNOWN")
    action          = attr_property("action")
    enctype         = attr_property("enctype", default = "application/x-www-form-urlencoded")
    method          = attr_property("method", default = "get")
    target          = attr_property("target")

    def submit(self):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

