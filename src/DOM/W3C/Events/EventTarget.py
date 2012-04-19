#!/usr/bin/env python
from __future__ import with_statement

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class EventTarget:
    def __init__(self):
        pass

    def addEventListener(self, eventType, listener, capture = False):
        log.info('addEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        
        try:
            self.tag._listeners.add((eventType, listener, capture))
        except:
            self.tag._listeners = set()
            self.tag._listeners.add((eventType, listener, capture))

        # addEventListener does NOT invoke the listener function
        # Uncomment the following line just for testing
        #listener.__call__()

    def removeEventListener(self, eventType, listener, capture = False):
        log.info('removeEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        
        try:
            self.tag._listeners.remove((eventType, listener, capture))
        except:
            pass

        # removeEventListener does NOT invoke the listener function
        # Uncomment the following line just for testing
        #listener.__call__()

    def _get_listeners(self, tag):
        capture_listeners  = [listener for (eventType, listener, capture) in tag._listeners if capture is True]
        bubbling_listeners = [listener for (eventType, listener, capture) in tag._listeners if capture is False]
        return capture_listeners, bubbling_listeners

    def _dispatchCaptureEvent(self, tag):
        if tag.parent is None:
            return

        self._dispatchCaptureEvent(tag.parent)
        if not tag.parent._listeners:
            return

        capture_listeners, bubbling_listeners = self._get_listeners(tag.parent)
        for c in capture_listeners:
            with self.doc.window.context as ctx:
                c()

    def _dispatchBubblingEvent(self, tag):
        for node in tag.parents:
            if node is None:
                break
            
            if not node._listeners:
                continue

            capture_listeners, bubbling_listeners = self._get_listeners(node)
            for c in bubbling_listeners:
                with self.doc.window.context as ctx:
                    c()

    def dispatchEvent(self, evt):
        log.info('dispatchEvent(%s)' % (evt, ))
        capture_listeners, bubbling_listeners = self._get_listeners(self.tag)

        if capture_listeners:
            self._dispatchCaptureEvent(self.tag)
   
        for c in capture_listeners:
            with self.doc.window.context as ctx:
                c()

        for c in bubbling_listeners:
            with self.doc.window.context as ctx:
                c()

        if bubbling_listeners:
            self._dispatchBubblingEvent(self.tag)

        return True

