#!/usr/bin/env python

import logging

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property
from .text_property import text_property

log = logging.getLogger("Thug")


class HTMLScriptElement(HTMLElement):
    _async  = bool_property("async", readonly = True, novalue = True)
    text    = text_property()
    htmlFor = None
    event   = None
    charset = attr_property("charset", default = "")
    defer   = bool_property("defer", readonly = True, novalue = True)
    _src    = attr_property("src", default = "")
    type    = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    def __getattr__(self, name):
        if name in ("async", ):
            return self._async

        raise AttributeError

    def get_src(self):
        return self._src

    def set_src(self, src):
        self._src = src
        log.DFT.handle_script(self.tag)

    src = property(get_src, set_src)
