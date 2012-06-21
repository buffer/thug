#!/usr/bin/env python

import bs4 as BeautifulSoup
from DOMException import DOMException
from Node import Node

class DocumentFragment(Node):
    def __init__(self, doc):
        self.tag = BeautifulSoup.Tag(parser = doc, name = 'documentfragment')
        Node.__init__(self, doc)

    @property
    def nodeName(self):
        return "#document-fragment"

    @property
    def nodeType(self):
        return Node.DOCUMENT_FRAGMENT_NODE

    @property
    def nodeValue(self):
        return None

