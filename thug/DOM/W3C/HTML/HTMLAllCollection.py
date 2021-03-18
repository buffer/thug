#!/usr/bin/env python

from .HTMLCollection import HTMLCollection


class HTMLAllCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def tags(self, name):
        from thug.DOM.W3C.Core.NodeList import NodeList

        nodes = list(self.doc.find_all(name.lower()))
        return NodeList(self.doc, nodes)
