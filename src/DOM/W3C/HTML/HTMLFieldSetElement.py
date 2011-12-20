#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement

class HTMLFieldSetElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def form(self):
        pass

