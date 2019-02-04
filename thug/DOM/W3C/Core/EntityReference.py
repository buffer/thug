#!/usr/bin/env python

import bs4 as BeautifulSoup

from .Node import Node


class EntityReference(Node):
    def __init__(self, doc, name):
        self.tag = BeautifulSoup.BeautifulSoup("&{};".format(name), "lxml")
        Node.__init__(self, doc)

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
