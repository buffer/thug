#!/usr/bin/env python


class HTMLDocumentCompatibleInfo(object):
    """
    IHTMLDocumentCompatibleInfo provides information about the
    compatibity mode specified by the web page. If the web page
    specifies multiple compatibility modes, they can be retrieved
    using IHTMLDocumentCompatibleInfoCollection.

    http://msdn.microsoft.com/en-us/library/cc288659(v=vs.85).aspx

    There are no standards that apply here.
    """
    def __init__(self, useragent = '', version = ''):
        self._userAgent = useragent
        self._version   = version

    def getUserAgent(self):
        return self._userAgent

    def setUserAgent(self, useragent): # pragma: no cover
        self._userAgent = useragent

    userAgent = property(getUserAgent, setUserAgent)

    def getVersion(self):
        return self._version

    def setVersion(self, version): # pragma: no cover
        self._version = version

    version = property(getVersion, setVersion)
