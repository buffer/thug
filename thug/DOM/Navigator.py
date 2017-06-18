#!/usr/bin/env python
#
# Navigator.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA


import os
import hashlib
import logging

from .JSClass import JSClass
from .MimeTypes import MimeTypes
from .Plugins import Plugins
from .UserProfile import UserProfile
from .HTTPSessionException import AboutBlank
from .HTTPSessionException import FetchForbidden
from .HTTPSessionException import InvalidUrl
from .HTTPSessionException import ThresholdExpired
from thug.Magic.Magic import Magic

log = logging.getLogger("Thug")


class Navigator(JSClass):
    def __init__(self, personality, window = None):
        self.personality = log.ThugOpts.Personality[personality]
        self._plugins    = Plugins()  # An array of the plugins installed in the browser
        self._mimeTypes  = MimeTypes()
        self._window     = window

        for p in self._mimeTypes.values():
            self._plugins.append(p['enabledPlugin'])

        self.__init_personality()
        self.filecount = 0

    def __init_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_personality_Safari()
            return

        if log.ThugOpts.Personality.isOpera():
            self.__init_personality_Opera()

    def __init_personality_IE(self):
        self.mimeTypes       = dict()
        self.plugins         = self._plugins
        self.taintEnabled    = self._taintEnabled
        self.appMinorVersion = self._appMinorVersion
        self.cpuClass        = self._cpuClass
        self.browserLanguage = self._browserLanguage
        self.systemLanguage  = self._systemLanguage
        self.userLanguage    = self._userLanguage

        if log.ThugOpts.Personality.browserMajorVersion < 9:
            self.userProfile = UserProfile()

    def __init_personality_Firefox(self):
        self.mimeTypes    = self._mimeTypes
        self.plugins      = self._plugins
        self.taintEnabled = self._taintEnabled
        self.oscpu        = self._oscpu
        self.buildID      = self._buildID
        self.product      = self._product
        self.productSub   = self._productSub
        self.vendor       = self._vendor
        self.vendorSub    = self._vendorSub
        self.language     = self._language
        self.preference   = self._preference

        self.registerContentHandler  = self._registerContentHandler
        self.registerProtocolHandler = self._registerProtocolHandler

    def __init_personality_Chrome(self):
        self.mimeTypes  = self._mimeTypes
        self.plugins    = self._plugins
        self.product    = self._product
        self.productSub = self._productSub
        self.vendor     = self._vendor
        self.vendorSub  = self._vendorSub
        self.language   = self._language

    def __init_personality_Safari(self):
        self.mimeTypes  = self._mimeTypes
        self.plugins    = self._plugins
        self.product    = self._product
        self.productSub = self._productSub
        self.vendor     = self._vendor
        self.vendorSub  = self._vendorSub
        self.language   = self._language

    def __init_personality_Opera(self):
        self.mimeTypes       = self._mimeTypes
        self.plugins         = self._plugins
        self.taintEnabled    = self._taintEnabled
        self.appMinorVersion = self._appMinorVersion
        self.browserLanguage = self._browserLanguage
        self.language        = self._language
        self.userLanguage    = self._userLanguage

    @property
    def window(self):
        return self._window

    @property
    def appCodeName(self):
        """
            The internal "code" name of the current browser
        """
        return self.personality['appCodeName']

    @property
    def appName(self):
        """
            The official name of the browser
        """
        return self.personality['appName']

    @property
    def appVersion(self):
        """
            The version of the browser as a string
        """
        return self.personality['appVersion']

    @property
    def userAgent(self):
        """
            The user agent string for the current browser
        """
        return self.personality['userAgent']

    @property
    def _buildID(self):
        """
            The build identifier of the browser (e.g. "2006090803")
        """
        return self.personality['buildID']

    @property
    def cookieEnabled(self):
        """
            A boolean indicating whether cookies are enabled
        """
        return True

    @property
    def _language(self):
        """
            A string representing the language version of the browser
        """
        return "en"

    @property
    def onLine(self):
        """
            A boolean indicating whether the browser is working online
        """
        return True

    @property
    def _oscpu(self):
        """
            A string that represents the current operating system
        """
        return self.personality['oscpu']

    @property
    def platform(self):
        """
            A string representing the platform of the browser
        """
        return self.personality['platform']

    @property
    def _product(self):
        """
            The product name of the current browser (e.g. "Gecko")
        """
        return self.personality['product']

    @property
    def _productSub(self):
        """
            The build number of the current browser (e.g. "20060909")
        """
        return self.personality['productSub']

    @property
    def securityPolicy(self):
        """
            An empty string. In Netscape 4.7x, returns "US & CA domestic policy" or "Export policy".
        """
        return ""

    @property
    def _vendor(self):
        """
            The vendor name of the current browser (e.g. "Netscape6")
        """
        return self.personality['vendor']

    @property
    def _vendorSub(self):
        """
            The vendor name of the current browser (e.g. "Netscape6")
        """
        return self.personality['vendorSub']

    @property
    def _appMinorVersion(self):
        return self.personality['appMinorVersion']

    @property
    def _browserLanguage(self):
        return "en"

    @property
    def _cpuClass(self):
        return "x86"

    @property
    def _systemLanguage(self):
        return "en"

    @property
    def _userLanguage(self):
        return "en"

    # Indicates whether the host browser is Java-enabled or not.
    def javaEnabled(self, *arg):
        return True

    # Lets code check to see if the document at a given URI is
    # available without using the network.
    def mozIsLocallyAvailable(self, *arg):
        return False

    # Sets a user preference.
    # self method is only available to privileged code, and you
    # should use XPCOM Preferences API instead.
    def _preference(self, *arg):
        pass

    # Allows web sites to register themselves as a possible handler
    # for a given MIME type.
    def _registerContentHandler(self, *arg):
        pass

    # New in Firefox 3
    # Allows web sites to register themselves as a possible handler
    # for a given protocol.
    def _registerProtocolHandler(self, *arg):
        pass

    # Obsolete
    # JavaScript taint/untaint functions removed in JavaScript 1.2[1]
    def _taintEnabled(self, *arg):
        return True

    def fetch(self, url, method = "GET", headers = None, body = None, redirect_type = None, params = None, snippet = None):
        log.URLClassifier.classify(url)

        # The command-line option -x (--local-nofetch) prevents remote
        # content fetching so raise an exception and exit the method.
        if log.HTTPSession.no_fetch:
            raise FetchForbidden

        # Do not attempt to fetch content if the URL is "about:blank".
        if log.HTTPSession.about_blank(url):
            raise AboutBlank

        # URL normalization and fixing (if broken and the option is
        # enabled).
        url = log.HTTPSession.normalize_url(self._window, url)
        if url is None:
            raise InvalidUrl

        last_url = getattr(log, 'last_url', None)
        if last_url is None:
            last_url = self._window.url

        if redirect_type:
            log.ThugLogging.add_behavior_warn("[{} redirection] {} -> {}".format(redirect_type, last_url, url), snippet = snippet)
            log.ThugLogging.log_connection(last_url, url, redirect_type)
        else:
            log.ThugLogging.log_connection(last_url, url, "unknown")

        # The command-line option -t (--threshold) defines the maximum
        # number of pages to fetch. If the threshold is reached avoid
        # fetching the contents.
        if log.HTTPSession.threshold_expired(url):
            raise ThresholdExpired

        if headers is None:
            headers = dict()

        response = log.HTTPSession.fetch(url, method, self._window, self.userAgent, headers, body)
        if response is None:
            return None

        _url = log.ThugLogging.log_redirect(response, self._window)
        if _url:
            url = _url

        referer = response.request.headers.get('referer', 'None')
        log.ThugLogging.add_behavior_warn("[HTTP] URL: {} (Status: {}, Referer: {})".format(url, response.status_code, referer), snippet = snippet)

        ctype     = response.headers.get('content-type', 'unknown')
        mime_base = os.path.join(log.ThugLogging.baseDir, ctype)

        md5 = hashlib.md5()
        md5.update(response.content)
        sha256 = hashlib.sha256()
        sha256.update(response.content)

        mtype = Magic(response.content).get_mime()

        data = {
            "content" : response.content,
            "status"  : response.status_code,
            "md5"     : md5.hexdigest(),
            "sha256"  : sha256.hexdigest(),
            "fsize"   : len(response.content),
            "ctype"   : ctype,
            "mtype"   : mtype
        }

        log.ThugLogging.add_behavior_warn("[HTTP] URL: {} (Content-type: {}, MD5: {})".format(response.url, ctype, data["md5"]), snippet = snippet)
        log.ThugLogging.log_location(url, data)

        if response.history:
            location = response.headers.get('location', None)
            if location and redirect_type not in ("URL found", "JNLP", "iframe", ):
                self._window.url = location

        if redirect_type in ("meta", ):
            self._window.url = url

        log.ThugLogging.store_content(mime_base, data["md5"], response.content)
        log.ThugLogging.log_file(response.content, response.url, params)

        if redirect_type in (None, 'window open', 'iframe', 'http-redirect', 'meta', ):
            log.last_url = response.url

        return response
