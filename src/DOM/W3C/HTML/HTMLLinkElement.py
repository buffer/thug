#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLLinkElement(HTMLElement):
    disabled        = False
    charset         = attr_property("charset")
    href            = attr_property("href")
    hreflang        = attr_property("hreflang")
    media           = attr_property("media")
    rel             = attr_property("rel")
    rev             = attr_property("rev")
    target          = attr_property("target")
    type            = attr_property("type")

