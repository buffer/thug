#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .text_property import text_property


class HTMLTitleElement(HTMLElement):
    text = text_property()

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
