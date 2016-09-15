#!/usr/bin/env python

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from .HTMLCollection import HTMLCollection
from NodeList import NodeList

class HTMLAllCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def tags(self, name):
        s = [p for p in self.doc.find_all(name.lower())]
        return NodeList(self.doc, s)
