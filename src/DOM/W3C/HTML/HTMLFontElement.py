#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property


class HTMLFontElement(HTMLElement):
    color           = attr_property("color")
    face            = attr_property("face")
    size            = attr_property("size")

