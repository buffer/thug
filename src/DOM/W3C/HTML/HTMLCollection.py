#!/usr/bin/env python

import sys, re, string

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from DOM.JSClass import JSClass

class HTMLCollection(JSClass):
    def __init__(self, doc, nodes):
        self.doc   = doc
        self.nodes = nodes

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        try:
            return self.item(int(key))
        except TypeError:
            return self.namedItem(str(key))

    @property
    def length(self):
        return len(self.nodes)

    def item(self, index):
        from DOMImplementation import DOMImplementation

        node = self.nodes[index]

        return DOMImplementation.createHTMLElement(self.doc, node) if node else None

    def namedItem(self, name):
        from DOMImplementation import DOMImplementation

        for node in self.nodes:
            if node.nodeName == name:
                return DOMImplementation.createHTMLElement(self.doc, node) if node else None

        return None
