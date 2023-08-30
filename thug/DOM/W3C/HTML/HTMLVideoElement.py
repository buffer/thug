#!/usr/bin/env python

import logging

from .HTMLMediaElement import HTMLMediaElement

log = logging.getLogger("Thug")


class HTMLVideoElement(HTMLMediaElement):
    def __init__(self, doc, tag):
        self._width       = 0
        self._height      = 0
        self._videoWidth  = 0
        self._videoHeight = 0
        self._poster      = ""
        self._playsInline = False

        HTMLMediaElement.__init__(self, doc, tag)

    def getWidth(self):
        return self._width

    def setWidth(self, width):
        self._width = width

    width = property(getWidth, setWidth)

    def getHeight(self):
        return self._height

    def setHeight(self, height):
        self._height = height

    height = property(getHeight, setHeight)

    def getVideoWidth(self):
        return self._videoWidth

    def setVideoWidth(self, videowidth):
        self._videoWidth = videowidth

    videoWidth = property(getVideoWidth, setVideoWidth)

    def getVideoHeight(self):
        return self._videoHeight

    def setVideoHeight(self, videoheight):
        self._videoHeight = videoheight

    videoHeight = property(getVideoHeight, setVideoHeight)

    def getPoster(self):
        return self._poster

    def setPoster(self, poster):
        self._poster = poster

    poster = property(getPoster, setPoster)

    def getPlaysInline(self):
        return self._playsInline

    def setPlaysInline(self, playsinline):
        self._playsInline = bool(playsinline)

    playsInline = property(getPlaysInline, setPlaysInline)
