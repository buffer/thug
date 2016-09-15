#!/usr/bin/env python

import re

from .Node import Node

class DocumentType(Node):
    RE_DOCTYPE = re.compile("^DOCTYPE (\w+)", re.M + re.S)
    
    def __init__(self, doc, tag):
        self.tag = tag
        Node.__init__(self, doc)
        self.parse(tag)
        
    def parse(self, text):
        m = self.RE_DOCTYPE.match(text)
        
        self._name = m.group(1) if m else ""
        
    @property
    def name(self):
        return self._name

    @property
    def nodeName(self):
        return self._name

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
        # FIXME
        return None

    # Introduced in DOM Level 2
    @property
    def publicId(self):
        pass

    # Introduced in DOM Level 2
    @property
    def systemId(self):
        pass

    # Introduced in DOM Level 2
    @property
    def internalSubset(self):
        pass
