#!/usr/bin/env python

import logging
import re

from .Node import Node

log = logging.getLogger("Thug")


class DocumentType(Node):
    RE_DOCTYPE = re.compile(r"^(\w+)", re.M + re.S)

    def __init__(self, doc, tag):
        self.tag = tag
        Node.__init__(self, doc)

    @property
    def name(self):
        m = self.RE_DOCTYPE.match(self.tag)
        return m.group(1) if m else ""

    @property
    def nodeName(self):
        return self.name

    @property
    def nodeType(self):
        return Node.DOCUMENT_TYPE_NODE

    @property
    def nodeValue(self):
        return None

    @property
    def entities(self):
        raise NotImplementedError()

    @property
    def notations(self):
        raise NotImplementedError()

    # Modified in DOM Level 2
    @property
    def ownerDocument(self):
        return log.DFT.window.doc

    # Introduced in DOM Level 2
    @property
    def publicId(self):
        return " "

    # Introduced in DOM Level 2
    @property
    def systemId(self):
        return " "

    # Introduced in DOM Level 2
    @property
    def internalSubset(self):
        return None

    # Introduced in DOM Level 3
    @property
    def textContent(self):
        return None
