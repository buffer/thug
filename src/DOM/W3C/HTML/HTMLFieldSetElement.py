#!/usr/bin/env python

from .HTMLElement import HTMLElement

class HTMLFieldSetElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def form(self):
        pass

