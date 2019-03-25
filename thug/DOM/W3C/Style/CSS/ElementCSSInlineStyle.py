#!/usr/bin/env python

from .CSSStyleDeclaration import CSSStyleDeclaration


class ElementCSSInlineStyle(object):
    def __init__(self, doc, tag):
        self.doc = doc
        self.tag = tag

        self._style = None

    @property
    def style(self):
        if self._style is None:
            self._style = CSSStyleDeclaration(self.tag['style'] if self.tag.has_attr('style') else '')

        return self._style
