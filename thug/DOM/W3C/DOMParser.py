#!/usr/bin/env python

import bs4 as BeautifulSoup


class DOMParser(object):
    def parseFromString(self, s, type_):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        parser = "lxml" if 'xml' in type_ else "html.parser"
        return DOMImplementation(BeautifulSoup.BeautifulSoup(s, parser))
