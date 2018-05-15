#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .text_property import text_property

import logging

log = logging.getLogger("Thug")


class HTMLScriptElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    async   = attr_property("async", bool)
    text    = text_property()
    htmlFor = None
    event   = None
    charset = attr_property("charset", default = "")
    defer   = attr_property("defer", bool)
    _src    = attr_property("src", default = "")
    type    = attr_property("type")

    def get_src(self):
        return self._src

    def set_src(self, src):
        self._src = src
        log.DFT.handle_script(self.tag)

    src = property(get_src, set_src)
