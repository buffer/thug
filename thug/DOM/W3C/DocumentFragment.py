#!/usr/bin/env python

import logging
import bs4 as BeautifulSoup

from .Node import Node
from .NodeList import NodeList

log = logging.getLogger("Thug")


class DocumentFragment(Node):
    def __init__(self, doc):
        self.tag = BeautifulSoup.Tag(parser = doc, name = 'documentfragment')
        Node.__init__(self, doc)
        self.__init_personality()

    def __init_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_personality_Safari()
            return

        if log.ThugOpts.Personality.isOpera():
            self.__init_personality_Opera()

    def __init_personality_IE(self):
        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.querySelectorAll = self._querySelectorAll
            self.querySelector    = self._querySelector

    def __init_personality_Firefox(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def __init_personality_Chrome(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def __init_personality_Safari(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def __init_personality_Opera(self):
        self.querySelectorAll = self._querySelectorAll
        self.querySelector    = self._querySelector

    def _querySelectorAll(self, selectors):
        try:
            s = self.tag.select(selectors)
        except:  # pylint:disable=bare-except
            return NodeList(self.doc, [])

        return NodeList(self.doc, s)

    def _querySelector(self, selectors):
        from .DOMImplementation import DOMImplementation

        try:
            s = self.tag.select(selectors)
        except:  # pylint:disable=bare-except
            return None

        if s and s[0]:
            return DOMImplementation.createHTMLElement(self, s[0])

        return None

    @property
    def nodeName(self):
        return "#document-fragment"

    @property
    def nodeType(self):
        return Node.DOCUMENT_FRAGMENT_NODE

    @property
    def nodeValue(self):
        return None
