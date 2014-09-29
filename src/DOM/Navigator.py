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


import PyV8
import os
import httplib2
import hashlib
import logging
import socket
import magic
import datetime
import urllib
import re
import ssl

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from .MimeTypes import MimeTypes
from .Plugins import Plugins
from .UserProfile import UserProfile

log = logging.getLogger("Thug")


class AboutBlank(httplib2.HttpLib2Error): 
    pass

class FetchForbidden(httplib2.HttpLib2Error):
    pass

class Navigator(PyV8.JSClass):
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

        if log.ThugOpts.Personality.browserVersion < '9.0':
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

    def __build_http_headers(self, headers):
        http_headers = {
            'Cache-Control'   : 'no-cache',
            'Accept-Language' : 'en-US',
            'Accept'          : '*/*',
            'User-Agent'      :  self.userAgent
        }

        if self._window.url not in ('about:blank', ):
            http_headers['Referer'] = self._normalize_url(self._window.url)

        if self._window.doc.cookie:
            http_headers['Cookie'] = self._window.doc.cookie

        if headers:
            for name, value in headers.items():
                http_headers[name] = value

        return http_headers

    def __normalize_protocol_relative_url(self, url):
        if self._window.url in ('about:blank', ):
            return 'http:%s' % (url, )

        _base_url = urlparse.urlparse(self._window.url)
        if not _base_url.scheme:
            return 'http:%s' % (url, )

        return "%s:%s" % (_base_url.scheme, url)

    def _check_compatibility(self, url, scheme):
        return url.startswith("%s:/" % (scheme, )) and not url.startswith("%s://" % (scheme, ))

    def _normalize_url(self, url):
        if log.ThugOpts.broken_url:
            for scheme in ("http", "https", ):
                if self._check_compatibility(url, scheme):
                    url = "%s://%s" % (scheme, url.split("%s:/" % (scheme, ))[1], ) 

        if url.startswith('//'):
            url = self.__normalize_protocol_relative_url(url)

        url = urllib.quote(url, safe = "%/:=&?~#+!$,;'@()*[]")
        _url = urlparse.urlparse(url)

        handler = getattr(log.SchemeHandler, 'handle_%s' % (_url.scheme, ), None)
        if handler:
            handler(self._window, url)
            return None

        if not _url.netloc:
            _url = urlparse.urljoin(self._window.url, url)
            log.warning("[Navigator URL Translation] %s --> %s" % (url, _url, ))
            return _url

        return url

    def fetch(self, url, method = "GET", headers = None, body = None, redirect_type = None, params = None):
        httplib2.debuglevel = log.ThugOpts.http_debug

        if re.match('^https', url, re.IGNORECASE):
           ssl_host = url.split('//')[1];
           cert_file = ssl.get_server_certificate((ssl_host,443))
           log.ThugLogging.add_behavior_warn("[Certificate]\n %s" % (cert_file, ))

        # The command-line option -x (--local-nofetch) prevents remote content
        # fetching so we raise an exception and exit the method.
        if log.ThugOpts.no_fetch:
            raise FetchForbidden

        if url == 'about:blank':
            raise AboutBlank

        url = self._normalize_url(url)
        if url is None:
            return

        if redirect_type:
            log.ThugLogging.add_behavior_warn(("[%s redirection] %s -> %s" % (redirect_type, self._window.url, url, )))
            log.ThugLogging.log_connection(self._window.url, url, redirect_type)
        else:
            log.ThugLogging.log_connection(self._window.url, url, "unknown")

        self.filecount += 1

        # The command-line option -t (--threshold) defines the maximum number of
        # pages to fetch. If the threshold is reached we avoid fetching the
        # contents.
        if log.ThugOpts.threshold and self.filecount >= log.ThugOpts.threshold:
            log.ThugLogging.log_location(url, None, flags = {"error" : "Threshold Exceeded"})
            return

        # The command-line option -T (--timeout) set the analysis timeout (in
        # seconds). If the analysis lasts more than this value we avoid fetching
        # the contents.
        if log.ThugOpts.timeout is not None and datetime.datetime.now() > log.ThugOpts.timeout:
            log.ThugLogging.log_location(url, None, flags = {"error" : "Timeout"})
            return

        http_headers = self.__build_http_headers(headers)

        h = httplib2.Http(cache      = log.ThugOpts.cache,
                          proxy_info = log.ThugOpts.proxy_info,
                          timeout    = 10,
                          disable_ssl_certificate_validation = True)

        h.force_exception_to_status_code = True

        response, content = h.request(url,
                                      method.upper(),
                                      body,
                                      redirections = 1024,
                                      headers = http_headers)

        _url = log.ThugLogging.log_redirect(response)
        if _url:
            url = _url

        log.URLClassifier.classify(url)

        referrer = http_headers['Referer'] if 'Referer' in http_headers else 'None'
        log.ThugLogging.add_behavior_warn("[HTTP] URL: %s (Status: %s, Referrer: %s)" % (url, response['status'], referrer, ))

        if response.status == 404:
            log.ThugLogging.add_behavior_warn("[File Not Found] URL: %s" % (url, ))
            log.ThugLogging.log_location(url, None, flags = {"error" : "File Not Found"})
            return response, content

        if response.status in (400, 408, 500, ):
            log.ThugLogging.add_behavior_warn("[%s] URL: %s" % (response.reason, url, ))
            return response, ''

        mime_base = log.ThugLogging.baseDir
        if 'content-type' in response:
            mime_base = os.path.join(mime_base, response['content-type'])

        md5 = hashlib.md5()
        md5.update(content)
        sha256 = hashlib.sha256()
        sha256.update(content)

        ctype     = response['content-type'] if 'content-type' in response else 'unknown'
        clocation = response['content-location'] if 'content-location' in response else url

        try:
            mtype = magic.from_buffer(content)
        except:
            # Ubuntu workaround
            # There is an old pymagic version in Ubuntu
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            mtype = ms.buffer(content)

        data = {"content" : content,
                "md5"     : md5.hexdigest(),
                "sha256"  : sha256.hexdigest(),
                "fsize"   : len(content),
                "ctype"   : ctype,
                "mtype"   : mtype}

        log.ThugLogging.add_behavior_warn("[HTTP] URL: %s (Content-type: %s, MD5: %s)" % (clocation, ctype, data["md5"]))
        log.ThugLogging.log_location(url, data)

        if response.previous and 'content-location' in response and response['content-location']:
            if redirect_type not in ("URL found", "JNLP", "iframe", ):
                self._window.url = response['content-location']

        if redirect_type in ("meta", ):
            self._window.url = url

        log.ThugLogging.store_content(mime_base, data["md5"], content)
        log.ThugLogging.log_file(content, url, params)
        return response, content
