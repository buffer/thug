#!/usr/bin/env python

import logging
import bs4

from .Node import Node

log = logging.getLogger("Thug")


class DocumentFragment(Node):
    def __init__(self, doc):
        self.tag = bs4.Tag(parser = doc, name = 'documentfragment')
        Node.__init__(self, doc)
        self.__init_documentfragment_personality()

    def __init_documentfragment_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_documentfragment_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_documentfragment_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_documentfragment_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_documentfragment_personality_Safari()
            return

    def __init_documentfragment_personality_IE(self):
        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.querySelectorAll = self._querySelectorAll
            self.querySelector    = self._querySelector

    def __init_documentfragment_personality_Firefox(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def __init_documentfragment_personality_Chrome(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def __init_documentfragment_personality_Safari(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def _querySelectorAll(self, selectors):
        from .NodeList import NodeList

        try:
            s = self.tag.select(selectors)
        except Exception: # pragma: no cover
            return NodeList(self.doc, [])

        return NodeList(self.doc, s)

    def _querySelector(self, selectors):
        from .DOMImplementation import DOMImplementation

        try:
            s = self.tag.select(selectors)
        except Exception: # pragma: no cover
            return None

        return DOMImplementation.createHTMLElement(self, s[0]) if s and s[0] else None

    @property
    def nodeName(self):
        return "#document-fragment"

    @property
    def nodeType(self):
        return Node.DOCUMENT_FRAGMENT_NODE

    @property
    def nodeValue(self):
        return None
