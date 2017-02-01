#!/usr/bin/env python

from .HTMLElement import HTMLElement


class HTMLSpanElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
