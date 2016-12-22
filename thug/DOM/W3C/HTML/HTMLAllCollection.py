#!/usr/bin/env python

from .HTMLCollection import HTMLCollection
from thug.DOM.W3C.NodeList import NodeList


class HTMLAllCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def tags(self, name):
        s = [p for p in self.doc.find_all(name.lower())]
        return NodeList(self.doc, s)
