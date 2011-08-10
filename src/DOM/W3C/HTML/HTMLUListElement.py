#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property


class HTMLUListElement(HTMLElement):
    compact         = attr_property("compact", bool)
    type            = attr_property("type")

