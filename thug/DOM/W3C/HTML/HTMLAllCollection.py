#!/usr/bin/env python

from thug.DOM.W3C.NodeList import NodeList
from .HTMLCollection import HTMLCollection


class HTMLAllCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def tags(self, name):
        s = [p for p in self.doc.find_all(name.lower())]
        return NodeList(self.doc, s)
