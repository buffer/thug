#!/usr/bin/env python

import logging

from thug.DOM.JSClass import JSClass

log = logging.getLogger("Thug")


class NodeList(JSClass):
    def __init__(self, doc, nodes):
        self.doc = doc
        self.nodes = nodes

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        return self.item(int(key))

    def item(self, index):
        return (
            log.DOMImplementation.createHTMLElement(self.doc, self.nodes[index])
            if index in range(0, len(self.nodes))
            else None
        )

    @property
    def length(self):
        return len(self.nodes)
