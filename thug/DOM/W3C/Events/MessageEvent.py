#!/usr/bin/env python

from .Event import Event


class MessageEvent(Event):
    EventTypes = ('message', )

    def __init__(self, event_type = 'message', options = None):
        Event.__init__(self)
        self.initMessageEvent(event_type, options)

    def __init_options(self, options):
        _options = dict(options) if options else {}

        self._data        = _options.get('data', None) if _options else None
        self._origin      = _options.get('origin', '') if _options else None
        self._lastEventId = _options.get('lastEventId', '') if _options else None
        self._source      = _options.get('source', None) if _options else None
        self._ports       = _options.get('ports', []) if _options else []

    @property
    def data(self):
        return self._data

    @property
    def origin(self):
        return self._origin

    @property
    def lastEventId(self):
        return self._lastEventId

    @property
    def source(self):
        return self._source

    @property
    def ports(self):
        return self._ports

    def initMessageEvent(self, event_type = 'message', options = None):
        self._type = event_type
        self.__init_options(options)
