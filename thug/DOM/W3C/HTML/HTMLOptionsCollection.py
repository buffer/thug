#!/usr/bin/env python

from .HTMLCollection import HTMLCollection


# Introduced in DOM Level 2
class HTMLOptionsCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)
