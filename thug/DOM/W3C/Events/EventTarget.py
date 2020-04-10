#!/usr/bin/env python

import logging

from .Event import Event
from .EventException import EventException

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class EventTarget(object):
    def __init__(self):
        self.__init_eventtarget_personality()
        self.tag._listeners = list()

    def __init_eventtarget_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_eventtarget_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_eventtarget_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_eventtarget_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_eventtarget_personality_Safari()
            return

    def __init_eventtarget_personality_IE(self):
        if log.ThugOpts.Personality.browserMajorVersion < 11:
            self.__init_proprietary_ie_event_methods()

        if log.ThugOpts.Personality.browserMajorVersion >= 8:
            self.__init_event_methods()

    def __init_eventtarget_personality_Firefox(self):
        self.__init_event_methods()

    def __init_eventtarget_personality_Chrome(self):
        self.__init_event_methods()

    def __init_eventtarget_personality_Safari(self):
        self.__init_event_methods()

    def __init_proprietary_ie_event_methods(self):
        self.detachEvent = self._detachEvent

        def attachEvent(self, eventType, handler, prio = False):
            return self._attachEvent(eventType, handler, prio)

        setattr(self.__class__, 'attachEvent', attachEvent)

    def __init_event_methods(self):
        self.removeEventListener = self._removeEventListener

        def addEventListener(self, eventType, listener, capture = False):
            return self._addEventListener(eventType, listener, capture)

        setattr(self.__class__, 'addEventListener', addEventListener)

    def __insert_listener(self, eventType, listener, capture, prio):
        # A document element or other object may have more than one event
        # handler registered for a particular type of event. When an appropriate
        # event occurs, the browser must invoke all of the handlers, following
        # these rules of invocation order:
        #
        # - Handlers registered by setting an object property or HTML attribute,
        # if any, are always invoked first
        #
        # - Handlers registered with addEventListener() are invoked in the order
        # in which they were registered
        #
        # - Handlers registered with attachEvent() may be invoked in any order
        # and your code should not depend on sequential invocation
        #
        # The `prio' parameter is used for deciding if the handler has to be
        # appended at the end of the _listener list (addEventListener and
        # attachEvent) or at the beginning (setting an object property or HTML
        # attribute)
        if prio:
            self.tag._listeners.insert(0, (eventType, listener, capture))
        else:
            self.tag._listeners.append((eventType, listener, capture))

    def _addEventListener(self, eventType, listener, capture = False, prio = False):
        log.debug('_addEventListener(%s, \n%r, \n%s)', eventType, listener, capture)

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_addeventlistener_count()

        if getattr(self.tag, '_listeners', None) is None: # pragma: no cover
            self.tag._listeners = list()

        if not (eventType, listener, capture) in self.tag._listeners:
            self.__insert_listener(eventType, listener, capture, prio)
            return

        # attachEvent() allows the same event handler to be registered more than
        # once. When the event of the specified type occurs, the registered
        # function will be invoked as many times as it was registered
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
            self.__insert_listener(eventType, listener, capture, prio)

    def _removeEventListener(self, eventType, listener, capture = False):
        log.debug('_removeEventListener(%s, \n%r, \n%s)', eventType, listener, capture)

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_removeeventlistener_count()

        try:
            self.tag._listeners.remove((eventType, listener, capture))
        except Exception:
            pass

    def _attachEvent(self, eventType, handler, prio = False):
        log.debug('_attachEvent(%s, \n%r)', eventType, handler)

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_attachevent_count()

        if not eventType.startswith('on'): # pragma: no cover
            log.warning('[WARNING] attachEvent eventType: %s', eventType)

        self._addEventListener(eventType[2:], handler, False, prio)

    def _detachEvent(self, eventType, handler):
        log.debug('_detachEvent(%s, \n%r)', eventType, handler)

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_detachevent_count()

        if not eventType.startswith('on'): # pragma: no cover
            log.warning('[WARNING] detachEvent eventType: %s', eventType)

        self._removeEventListener(eventType[2:], handler)

    def _get_listeners(self, tag, evtType):
        _listeners         = [(eventType, listener, capture) for (eventType, listener, capture) in tag._listeners if eventType == evtType]
        capture_listeners  = [(eventType, listener, capture) for (eventType, listener, capture) in _listeners if capture is True]
        bubbling_listeners = [(eventType, listener, capture) for (eventType, listener, capture) in _listeners if capture is False]

        return capture_listeners, bubbling_listeners

    def _do_dispatch(self, c, evtObject):
        eventType, listener, capture = c  # pylint:disable=unused-variable

        self.doc.window.event = evtObject

        with self.doc.window.context:
            if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
                listener()
            else:
                listener(evtObject)

    def do_dispatch(self, c, evtObject):
        try:
            self._do_dispatch(c, evtObject)
        except Exception as e:
            eventType, listener, capture = c  # pylint:disable=unused-variable
            log.warning("[WARNING] Error while dispatching %s event (%s)", eventType, str(e))

    def _dispatchCaptureEvent(self, tag, evtType, evtObject):
        if tag.parent is None:
            return

        self._dispatchCaptureEvent(tag.parent, evtType, evtObject)

        if not tag.parent._listeners:
            return

        if evtObject._stoppedPropagation: # pragma: no cover
            return

        capture_listeners, bubbling_listeners = self._get_listeners(tag.parent, evtType)  # pylint:disable=unused-variable
        for c in capture_listeners:
            evtObject.currentTarget = tag.parent._node
            self.do_dispatch(c, evtObject)

    def _dispatchBubblingEvent(self, tag, evtType, evtObject):
        for node in tag.parents:
            if node is None: # pragma: no cover
                break

            if not node._listeners:
                continue

            if evtObject._stoppedPropagation: # pragma: no cover
                continue

            capture_listeners, bubbling_listeners = self._get_listeners(node, evtType)  # pylint:disable=unused-variable
            for c in bubbling_listeners:
                evtObject.currentTarget = node._node
                self.do_dispatch(c, evtObject)

    def dispatchEvent(self, evtObject):
        evtType = evtObject.type

        if not evtType:
            raise EventException(EventException.UNSPECIFIED_EVENT_TYPE_ERR)

        log.info('dispatchEvent(%s)', evtType)

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_dispatchevent_count()

        capture_listeners, bubbling_listeners = self._get_listeners(self.tag, evtType)

        if capture_listeners:
            evtObject.eventPhase = Event.CAPTURING_PHASE
            self._dispatchCaptureEvent(self.tag, evtType, evtObject)

        evtObject._target       = self
        evtObject.eventPhase    = Event.AT_TARGET
        evtObject.currentTarget = self

        if not evtObject._stoppedPropagation:
            for c in capture_listeners:
                self.do_dispatch(c, evtObject)

            for c in bubbling_listeners:
                self.do_dispatch(c, evtObject)

        if bubbling_listeners:
            evtObject.eventPhase = Event.BUBBLING_PHASE
            self._dispatchBubblingEvent(self.tag, evtType, evtObject)

        evtObject.eventPhase = Event.AT_TARGET
        return True
