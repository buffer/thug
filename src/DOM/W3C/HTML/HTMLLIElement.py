#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLLIElement(HTMLElement):
    type            = attr_property("type")
    value           = attr_property("value", long)

