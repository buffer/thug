#!/usr/bin/env python

from thug.DOM.JSClass import JSClass


class NodeList(JSClass):
    def __init__(self, doc, nodes):
        self.doc = doc
        self.nodes = nodes

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        return self.item(int(key))

    def item(self, index):
        from .DOMImplementation import DOMImplementation
        return DOMImplementation.createHTMLElement(self.doc, self.nodes[index]) if index >= 0 and index < len(self.nodes) else None

    @property
    def length(self):
        return len(self.nodes)
