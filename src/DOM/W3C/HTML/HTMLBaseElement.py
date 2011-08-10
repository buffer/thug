#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLBaseElement(HTMLElement):
    href            = attr_property("href")
    target          = attr_property("target")

