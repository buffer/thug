#!/usr/bin/env python
from __future__ import with_statement

from DOMException import DOMException
from Node import Node


class DocumentFragment(Node):
    def __init__(self, doc, tags):
        Node.__init__(self, doc)

        self.tags = tags

    @property
    def nodeName(self):
        return "#document-fragment"

    @property
    def nodeType(self):
        return Node.DOCUMENT_FRAGMENT_NODE

    @property
    def nodeValue(self):
        return None

