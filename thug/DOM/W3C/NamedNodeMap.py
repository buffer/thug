#!/usr/bin/env python

from thug.DOM.JSClass import JSClass


class NamedNodeMap(JSClass):
    def __init__(self, parent):
        self.parent = parent

    def getNamedItem(self, name):
        return self.parent.getAttributeNode(name)

    def __getattr__(self, name):
        return self.getNamedItem(name)

    def setNamedItem(self, attr):
        oldattr = self.parent.getAttributeNode(attr.name)

        attr.parent = self.parent

        self.parent.tag[attr.name] = attr.value

        if oldattr:
            oldattr.parent = None

        return oldattr

    def removeNamedItem(self, name):
        self.parent.removeAttribute(name)

    def item(self, index):
        names = list(self.parent.tag.attrMap.keys())
        return self.parent.getAttributeNode(names[index]) if 0 <= index and index < len(names) else None

    @property
    def length(self):
        return len(self.parent.tag._getAttrMap())
