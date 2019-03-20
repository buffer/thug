#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLBaseElement(HTMLElement):
    href   = attr_property("href")
    target = attr_property("target")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
