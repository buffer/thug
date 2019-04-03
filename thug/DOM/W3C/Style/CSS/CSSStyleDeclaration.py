#!/usr/bin/env python

import logging

from thug.DOM.JSClass import JSClass

log = logging.getLogger("Thug")


class CSSStyleDeclaration(JSClass):
    def __init__(self, style):
        self.props = dict()

        for prop in [p for p in style.split(';') if p]:
            k, v = prop.strip().split(':')
            self.props[k.strip()] = v.strip()

    @property
    def cssText(self):
        css_text = '; '.join(["%s: %s" % (k, v) for k, v in self.props.items()])
        return css_text + ';' if css_text else ''

    def getPropertyValue(self, name):
        return self.props.get(name, '')

    def removeProperty(self, name):
        return self.props.pop(name, '')

    @property
    def length(self):
        return len(self.props)

    def item(self, index):
        if index < 0 or index >= len(self.props):
            return ''

        return list(self.props.keys())[index]

    def __getattr__(self, name):
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 7 and name in ('maxHeight', ):
            raise AttributeError(name)

        return self.getPropertyValue(name)

    def __setattr__(self, name, value):
        if name in ('props', ):
            super(CSSStyleDeclaration, self).__setattr__(name, value)
        else:
            self.props[name] = value
