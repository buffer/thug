#!/usr/bin/env python

import sys
import PyV8

class NodeList(PyV8.JSClass):
    def __init__(self, doc, nodes):
        self.doc = doc
        self.nodes = nodes

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        return self.item(int(key))

    def item(self, index):
        from DOMImplementation import DOMImplementation
        return DOMImplementation.createHTMLElement(self.doc, self.nodes[index]) if 0 <= index and index < len(self.nodes) else None

    @property
    def length(self):
        return len(self.nodes)

    def tags(self, name):
        s = [p for p in self.doc.find_all(name.lower())]
        return NodeList(self.doc, s)
