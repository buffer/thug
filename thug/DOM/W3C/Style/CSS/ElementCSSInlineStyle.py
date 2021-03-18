#!/usr/bin/env python


class ElementCSSInlineStyle:
    def __init__(self, doc, tag):
        self.doc = doc
        self.tag = tag

        self._style = None

    @property
    def style(self):
        if self._style is None:
            from .CSSStyleDeclaration import CSSStyleDeclaration
            self._style = CSSStyleDeclaration(self.tag['style'] if self.tag.has_attr('style') else '')

        return self._style
