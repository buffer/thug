#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLLinkElement(HTMLElement):
    charset  = attr_property("charset", default = "")
    disabled = False
    href     = attr_property("href")
    hreflang = attr_property("hreflang")
    media    = attr_property("media")
    rel      = attr_property("rel")
    rev      = attr_property("rev")
    target   = attr_property("target")
    type     = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
