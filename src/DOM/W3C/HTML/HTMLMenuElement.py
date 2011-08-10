#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLMenuElement(HTMLElement):
    compact         = attr_property("compact", bool)

