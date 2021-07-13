#!/usr/bin/env python

from .HTMLCollection import HTMLCollection


class AudioTrackList(HTMLCollection):
    def __init__(self, doc, tracks):
        HTMLCollection.__init__(self, doc, tracks)
