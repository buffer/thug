#!/usr/bin/env python

from .CSSStyleDeclaration import CSSStyleDeclaration

class ElementCSSInlineStyle(object):
    def __init__(self, doc, tag):
        self.doc = doc
        self.tag = tag

    @property
    def style(self):
        return CSSStyleDeclaration(self.tag['style'] if self.tag.has_attr('style') else '')
