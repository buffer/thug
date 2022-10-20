#!/usr/bin/env python

import bs4

from .Node import Node


class EntityReference(Node):
    def __init__(self, doc, name):
        tag = bs4.BeautifulSoup(f"&{name};", "lxml")
        Node.__init__(self, doc, tag)

    @property
    def name(self):
        return self.tag.string.encode('utf8')

    @property
    def nodeName(self):
        return self.name

    @property
    def nodeType(self):
        return Node.ENTITY_REFERENCE_NODE

    @property
    def nodeValue(self):
        return None
