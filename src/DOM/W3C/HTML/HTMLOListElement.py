#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property


class HTMLOListElement(HTMLElement):
    compact         = attr_property("compact", bool)
    start           = attr_property("start", long)
    type            = attr_property("type")

