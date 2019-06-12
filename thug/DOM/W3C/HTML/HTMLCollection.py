#!/usr/bin/env python

import bs4

from thug.DOM.JSClass import JSClass


class HTMLCollection(JSClass):
    def __init__(self, doc, nodes):
        self.doc   = doc
        self.nodes = nodes

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        return self.item(int(key))

    def __delitem__(self, key): # pragma: no cover
        self.nodes.__delitem__(key)

    def __getattr__(self, key):
        return self.namedItem(key)

    @property
    def length(self):
        return len(self.nodes)

    def item(self, index):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        if index < 0 or index >= self.length:
            return None

        if isinstance(self.nodes[index], bs4.element.Tag):
            return DOMImplementation.createHTMLElement(self.doc, self.nodes[index])

        return self.nodes[index]

    def namedItem(self, name):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        for node in self.nodes:
            if 'id' in node.attrs and node.attrs['id'] in (name, ):
                return DOMImplementation.createHTMLElement(self.doc, node)

        for node in self.nodes:
            if 'name' in node.attrs and node.attrs['name'] in (name, ):
                return DOMImplementation.createHTMLElement(self.doc, node)

        return None
