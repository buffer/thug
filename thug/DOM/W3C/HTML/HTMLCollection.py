#!/usr/bin/env python

from thug.DOM.JSClass import JSClass


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
        # from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        node = self.nodes[index]

        return node
        # return DOMImplementation.createHTMLElement(self.doc, node) if node else None

    def namedItem(self, name):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        for node in self.nodes:
            if node.nodeName == name:
                return DOMImplementation.createHTMLElement(self.doc, node) if node else None

        return None
