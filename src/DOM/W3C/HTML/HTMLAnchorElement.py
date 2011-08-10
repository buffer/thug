#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLAnchorElement(HTMLElement):
    accessKey       = attr_property("accesskey")
    charset         = attr_property("charset")
    coords          = attr_property("coords")
    href            = attr_property("href")
    hreflang        = attr_property("hreflang")
    name            = attr_property("name")
    rel             = attr_property("rel")
    rev             = attr_property("rev")
    shape           = attr_property("shape")
    tabIndex        = attr_property("tabindex", long)
    target          = attr_property("target")
    type            = attr_property("type")

    def blur(self):
        pass

    def focus(self):
        pass

