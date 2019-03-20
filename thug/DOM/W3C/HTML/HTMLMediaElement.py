#!/usr/bin/env python

import logging

from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


# HTMLMediaElement.networkState possible values

NETWORK_EMPTY     = 0   # There is no data yet. Also, readyState is HAVE_NOTHING.
NETWORK_IDLE      = 1   # HTMLMediaElement is active and has selected a resource, but is not using the network.
NETWORK_LOADING   = 2   # The browser is downloading HTMLMediaElement data.
NETWORK_NO_SOURCE = 3   # No HTMLMediaElement src found.

# HTMLMediaElement.readyState possible values

HAVE_NOTHING      = 0   # No information is available about the media resource.
HAVE_METADATA     = 1   # Enough of the media resource has been retrieved that the metadata attributes are
                        # initialized. Seeking will no longer raise an exception.
HAVE_CURRENT_DATA = 2   # Data is available for the current playback position, but not enough to actually
                        # play more than one frame.
HAVE_FUTURE_DATA  = 3   # Data for the current playback position as well as for at least a little bit of time
                        # into the future is available (in other words, at least two frames of video, for example).
HAVE_ENOUGH_DATA  = 4   # Enough data is available - and the download rate is high enough - that the media can be
                        # played through to the end without interruption.


class HTMLMediaElement(HTMLElement):
    autoplay   = attr_property("autoplay", bool)
    controls   = attr_property("console", bool, readonly = True, default = False)
    loop       = attr_property("loop", bool, default = False)
    mediaGroup = attr_property("mediagroup")
    _src       = attr_property("src", default = "")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._paused = False

    def get_src(self):
        return self._src

    def set_src(self, src):
        self._src = src

        try:
            self.doc.window._navigator.fetch(src)
        except Exception:
            return

    src = property(get_src, set_src)

    @property
    def audioTracks(self):
        raise NotImplementedError()

    @property
    def buffered(self):
        raise NotImplementedError()

    @property
    def controller(self):
        return None

    @property
    def controlsList(self):
        raise NotImplementedError()

    @property
    def crossOrigin(self):
        return None

    @property
    def currentSrc(self):
        return self._src

    @property
    def currentTime(self):
        return 0

    @property
    def defaultMuted(self):
        return False

    @property
    def defaultPlaybackRate(self):
        return 1

    @property
    def disableRemotePlayback(self):
        return False

    @property
    def duration(self):
        return 0

    @property
    def ended(self):
        return False

    @property
    def error(self):
        return None

    @property
    def initialTime(self):
        return 0

    @property
    def mediaKeys(self):
        return None

    @property
    def muted(self):
        return False

    @property
    def networkState(self):
        return NETWORK_IDLE

    @property
    def paused(self):
        return self._paused

    @property
    def playbackRate(self):
        return 1

    @property
    def readyState(self):
        return HAVE_ENOUGH_DATA

    @property
    def sinkId(self):
        return ""

    @property
    def srcObject(self):
        return None

    @property
    def textTracks(self):
        raise NotImplementedError()

    def load(self):
        pass

    def pause(self):
        self._paused = True

    def play(self):
        self._paused = False
