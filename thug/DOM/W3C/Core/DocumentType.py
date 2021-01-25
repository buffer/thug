#!/usr/bin/env python

import logging
import re

from .Node import Node
from .NamedNodeMap import NamedNodeMap

log = logging.getLogger("Thug")


class DocumentType(Node):
    RE_DOCTYPE = re.compile(r"^(\w+)", re.M + re.S)

    def __init__(self, doc, tag):
        self.tag = tag
        Node.__init__(self, doc)
        self.__init_documenttype_personality()

    def __init_documenttype_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_node_personality_IE()

    def __init_node_personality_IE(self):
        if log.ThugOpts.Personality.browserMajorVersion in (9, ):
            self.entities = NamedNodeMap(self.doc, self.tag)
            self.notations = NamedNodeMap(self.doc, self.tag)

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
