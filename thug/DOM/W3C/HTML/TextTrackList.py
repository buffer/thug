#!/usr/bin/env python

from .HTMLCollection import HTMLCollection


class TextTrackList(HTMLCollection):
    def __init__(self, doc, tracks):
        HTMLCollection.__init__(self, doc, tracks)

    def getTrackById(self, id_): # pylint:disable=unused-argument
        return None
