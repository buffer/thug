#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

import logging

log = logging.getLogger("Thug")


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
        handler = getattr(log.DFT, 'handle_form', None)
        if handler:
            handler(self.tag)

    def reset(self):
        log.warning('[HTMLFormElement] reset method not defined')
