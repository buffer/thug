#!/usr/bin/env python

from .HTMLCollection import HTMLCollection


class HTMLFormControlsCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)
