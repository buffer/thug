#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property
from text_property import text_property

class HTMLScriptElement(HTMLElement):
    text            = text_property()
    htmlFor         = None
    event           = None
    charset         = attr_property("charset")
    defer           = attr_property("defer", bool)
    src             = attr_property("src")
    type            = attr_property("type")

