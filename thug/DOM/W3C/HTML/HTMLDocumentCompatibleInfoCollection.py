#!/usr/bin/env python

from .HTMLCollection import HTMLCollection


class HTMLDocumentCompatibleInfoCollection(HTMLCollection):
    """
    http://msdn.microsoft.com/en-us/library/hh826015(v=vs.85).aspx

    There are no standards that apply here.
    """

    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def __call__(self, item):
        return self.__getitem__(item)
