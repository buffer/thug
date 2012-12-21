#!/usr/bin/env python
#
# thug.py
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

import sys
import os
import errno
import getopt
import datetime
import urlparse
import hashlib
import httplib2
import logging

from DOM.W3C import w3c
from DOM.Personality import Personality
from DOM import Window, DFT, MIMEHandler, SchemeHandler
from Logging.ThugLogging import ThugLogging
from Plugins.ThugPlugins import *

__thug_version__ = '0.4.15'

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)


class ThugOpts(dict):
    proxy_schemes = ('http', 'socks4', 'socks5', )

    def __init__(self):
        self._proxy_info = None
        self.local       = False
        self.ast_debug   = False
        self._useragent  = 'winxpie60'
        self._referer    = 'about:blank'
        self._events     = list()
        self._delay      = 0
        self.Personality = Personality()

    def set_proxy_info(self, proxy):
        p = urlparse.urlparse(proxy)
        if p.scheme.lower() not in self.proxy_schemes:
            log.warning('[ERROR] Invalid proxy scheme (valid schemes: http, socks4, socks5)')
            sys.exit(0)

        proxy_type = getattr(httplib2.socks, "PROXY_TYPE_%s" % (p.scheme.upper(),))
        self._proxy_info = httplib2.ProxyInfo(proxy_type = proxy_type,
                                              proxy_host = p.hostname,
                                              proxy_port = p.port if p.port else 8080,
                                              proxy_user = p.username,
                                              proxy_pass = p.password)

    def get_proxy_info(self):
        return self._proxy_info

    proxy_info = property(get_proxy_info, set_proxy_info)

    def get_useragent(self):
        return self._useragent

    def set_useragent(self, useragent):
        if not useragent in self.Personality:
            log.warning('[WARNING] Invalid User Agent provided (using default "%s")' % (self._useragent, ))
            return

        self._useragent = useragent

    useragent = property(get_useragent, set_useragent)

    def get_referer(self):
        return self._referer

    def set_referer(self, referer):
        self._referer = referer

    referer = property(get_referer, set_referer)

    def get_events(self):
        return self._events

    def set_events(self, events):
        for e in events.split(","):
            self._events.append(e.lower().strip())

    events = property(get_events, set_events)

    def get_delay(self):
        return self._delay

    def set_delay(self, timeout):
        try:
            _timeout = int(timeout)
        except:
            log.warning('[WARNING] Ignoring invalid delay value (should be an integer)')
            return

        self._delay = abs(_timeout)

    delay = property(get_delay, set_delay)


class ThugVulnModules(dict):
    def __init__(self):
        self._acropdf_pdf               = '9.1.0'
        self._acropdf_disabled          = False
        self._shockwave_flash           = '10.0.64.0'
        self._shockwave_flash_disabled  = False
        self._javaplugin                = '1.6.0.32'
        self._javaplugin_disabled       = False

    def invalid_version(self, version):
        for p in version.split('.'):
            if not p.isdigit():
                return True

        return False

    def get_acropdf_pdf(self):
        return self._acropdf_pdf

    def set_acropdf_pdf(self, version):
        if self.invalid_version(version):
            log.warning('[WARNING] Invalid Adobe Acrobat Reader version provided (using default one)')
            return

        self._acropdf_pdf = version

    acropdf_pdf = property(get_acropdf_pdf, set_acropdf_pdf)

    def disable_acropdf(self):
        self._acropdf_disabled = True

    @property
    def acropdf_disabled(self):
        return self._acropdf_disabled

    def get_shockwave_flash(self):
        return self._shockwave_flash

    def set_shockwave_flash(self, version):
        if not version.split('.')[0] in ('8', '9', '10') or self.invalid_version(version):
            log.warning('[WARNING] Invalid Shockwave Flash version provided (using default one)')
            return

        self._shockwave_flash = version

    shockwave_flash = property(get_shockwave_flash, set_shockwave_flash)

    def disable_shockwave_flash(self):
        self._shockwave_flash_disabled = True

    @property
    def shockwave_flash_disabled(self):
        return self._shockwave_flash_disabled

    def get_javaplugin(self):
        javaplugin = self._javaplugin.split('.')
        last       = javaplugin.pop()
        return '%s_%s' % (''.join(javaplugin), last)

    def set_javaplugin(self, version):
        if self.invalid_version(version):
            log.warning('[WARNING] Invalid JavaPlugin version provided (using default one)')
            return

        _version = version.split('.')
        while len(_version) < 4:
            _version.append('0')

        if len(_version[3]) == 1:
            _version[3] = '0%s' % (_version[3], )

        self._javaplugin = '.'.join(_version)

    javaplugin = property(get_javaplugin, set_javaplugin)

    def disable_javaplugin(self):
        self._javaplugin_disabled = True

    @property
    def javaplugin_disabled(self):
        return self._javaplugin_disabled

    @property
    def javawebstart_isinstalled(self):
        javawebstart = self._javaplugin.split('.')
        last         = javawebstart.pop()
        return '%s.%s' % ('.'.join(javawebstart), '0')


class OpaqueFilter(logging.Filter):
        def __init__(self):
            pass

        def filter(self, record):
            return False


class Thug:
    def __init__(self, args):
        self.args               = args
        log.ThugLogging         = ThugLogging(__thug_version__)
        log.ThugOpts            = ThugOpts()
        log.ThugVulnModules     = ThugVulnModules()
        log.MIMEHandler         = MIMEHandler.MIMEHandler()
        log.SchemeHandler       = SchemeHandler.SchemeHandler()

    def __call__(self):
        self.analyze()

    def usage(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        python thug.py [ options ] url

    Options:
        -h, --help          \tDisplay this help information
        -V, --version       \tDisplay Thug version
        -u, --useragent=    \tSelect a user agent (see below for values, default: winxpie60)
        -e, --events=       \tEnable comma-separated specified DOM events handling
        -w, --delay=        \tSet a maximum setTimeout/setInterval delay value (in milliseconds)
        -n, --logdir=       \tSet the log output directory
        -o, --output=       \tLog to a specified file
        -r, --referer=      \tSpecify a referer
        -p, --proxy=        \tSpecify a proxy (see below for format and supported schemes)
        -l, --local
        -v, --verbose       \tEnable verbose mode
        -d, --debug         \tEnable debug mode
        -q, --quiet         \tDisable console logging
        -a, --ast-debug     \tEnable AST debug mode (requires debug mode)

        Plugins:
        -A, --adobepdf=     \tSpecify the Adobe Acrobat Reader version (default: 9.1.0)
        -P, --no-adobepdf   \tDisable Adobe Acrobat Reader plugin
        -S, --shockwave=    \tSpecify the Shockwave Flash version (default: 10.0.64.0)
        -R, --no-shockwave  \tDisable Shockwave Flash plugin
        -J, --javaplugin=   \tSpecify the JavaPlugin version (default: 1.6.0.32)
        -K, --no-javaplugin \tDisable Java plugin

    Proxy Format:
        scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)

    Available User-Agents:
"""
        for key, value in sorted(log.ThugOpts.Personality.iteritems(), key = lambda (k, v): (v['id'], k)):
            msg += "\t%s\t\t%s\n" % (key, value['description'], )

        print msg
        sys.exit(0)

    def version(self):
        print "Thug %s" % (__thug_version__, )
        sys.exit(0)

    def run(self, window):
        dft = DFT.DFT(window)
        dft.run()

    def run_local(self, url):
        log.ThugLogging.set_url(url)
        log.ThugOpts.local = True

        html   = open(url, 'r').read()
        doc    = w3c.parseString(html)
        window = Window.Window('about:blank', doc, personality = log.ThugOpts.useragent)
        window.open()
        self.run(window)

    def run_remote(self, url):
        if urlparse.urlparse(url).scheme is '':
            url = 'http://%s' % (url, )

        log.ThugLogging.set_url(url)

        doc    = w3c.parseString('')
        window = Window.Window(log.ThugOpts.referer, doc, personality = log.ThugOpts.useragent)
        window = window.open(url)
        if window:
            self.run(window)

    def analyze(self):
        p = getattr(self, 'run_remote', None)

        try:
            options, args = getopt.getopt(self.args, 'hVu:e:w:n:o:r:p:lvdqaA:PS:RJ:K',
                ['help',
                'version',
                'useragent=',
                'events=',
                'delay=',
                'logdir=',
                'output=',
                'referer=',
                'proxy=',
                'local',
                'verbose',
                'debug',
                'quiet',
                'ast-debug',
                'adobepdf=',
                'no-adobepdf',
                'shockwave=',
                'no-shockwave',
                'javaplugin=',
                'no-javaplugin',
                ])
        except getopt.GetoptError:
            self.usage()

        if not options and not args:
            self.usage()

        for option in options:
            if option[0] in ('-h', '--help'):
                self.usage()
            if option[0] in ('-V', '--version'):
                self.version()

        for option in options:
            if option[0] in ('-u', '--useragent', ):
                log.ThugOpts.useragent = option[1]
            if option[0] in ('-e', '--events'):
                log.ThugOpts.events = option[1]
            if option[0] in ('-w', '--delay'):
                log.ThugOpts.delay = option[1]
            if option[0] in ('-n', '--logdir'):
                log.ThugLogging.set_absbasedir(option[1])
            if option[0] in ('-r', '--referer', ):
                log.ThugOpts.referer = option[1]
            if option[0] in ('-p', '--proxy', ):
                log.ThugOpts.proxy_info = option[1]
            if option[0] in ('-l', '--local', ):
                p = getattr(self, 'run_local')
            if option[0] in ('-v', '--verbose', ):
                log.setLevel(logging.INFO)
            if option[0] in ('-d', '--debug', ):
                log.setLevel(logging.DEBUG)
            if option[0] in ('-a', '--ast-debug', ):
                log.ThugOpts.ast_debug = True
            if option[0] in ('-A', '--adobepdf', ):
                log.ThugVulnModules.acropdf_pdf = option[1]
            if option[0] in ('-P', '--no-adobepdf', ):
                log.ThugVulnModules.disable_acropdf()
            if option[0] in ('-S', '--shockwave', ):
                log.ThugVulnModules.shockwave_flash = option[1]
            if option[0] in ('-R', '--no-shockwave', ):
                log.ThugVulnModules.disable_shockwave_flash()
            if option[0] in ('-J', '--javaplugin', ):
                log.ThugVulnModules.javaplugin = option[1]
            if option[0] in ('-K', '--no-javaplugin', ):
                log.ThugVulnModules.disable_javaplugin()

        log.ThugLogging.set_basedir(args[0])

        for option in options:
            if option[0] in ('-o', '--output', ):
                fh = logging.FileHandler(os.path.join(log.ThugLogging.baseDir, option[1]))
                log.addHandler(fh)
            if option[0] in ('-q', '--quiet', ):
                root = logging.getLogger()
                for handler in root.handlers:
                    if isinstance(handler, logging.StreamHandler):
                        handler.addFilter(OpaqueFilter())

        if p:
            ThugPlugins(PRE_ANALYSIS_PLUGINS, self)()
            p(args[0])
            ThugPlugins(POST_ANALYSIS_PLUGINS, self)()

        log.ThugLogging.log_event()
        return log

if __name__ == "__main__":
    if not os.getenv('THUG_PROFILE', None):
        Thug(sys.argv[1:])()
    else:
        import cProfile
        import pstats
        cProfile.run('Thug(sys.argv[1:])()', 'countprof')
        p = pstats.Stats('countprof')
        p.print_stats()
