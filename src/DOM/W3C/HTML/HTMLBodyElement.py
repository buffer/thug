#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLBodyElement(HTMLElement):
    background      = attr_property("background")
    bgColor         = attr_property("bgcolor")
    link            = attr_property("link")
    aLink           = attr_property("alink")
    vLink           = attr_property("vlink")
    text            = attr_property("text")

