#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLParamElement(HTMLElement):
    name            = attr_property("name")
    type            = attr_property("type")
    value           = attr_property("value")
    valueType       = attr_property("valuetype")


