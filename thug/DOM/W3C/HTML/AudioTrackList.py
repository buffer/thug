#!/usr/bin/env python

from .HTMLElement import HTMLElement


class AudioTrackList(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self.tracks = list()

    def __len__(self):
        return self.length

    def __getitem__(self, index):
        return self.tracks[index] if index in range(0, len(self.tracks)) else None

    @property
    def length(self):
        return len(self.tracks)
