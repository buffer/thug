#!/usr/bin/env python
#
# DFT.py
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
import pylibemu
import string
import base64
import logging
import PyV8
import bs4 as BeautifulSoup
import jsbeautifier
import six
from cssutils.parse import CSSParser

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from .W3C import w3c
from .W3C.DOMImplementation import DOMImplementation
from .W3C.Events.Event import Event
from .W3C.Events.MouseEvent import MouseEvent
from .W3C.Events.HTMLEvent import HTMLEvent
from thug.ActiveX.ActiveX import _ActiveXObject

log        = logging.getLogger("Thug")

class DFT(object):
    javascript     = ('javascript', )
    vbscript       = ('vbs', 'vbscript', 'visualbasic')

    # Some event types are directed at the browser as a whole, rather than at 
    # any particular document element. In JavaScript, handlers for these events 
    # are registered on the Window object. In HTML, we place them on the <body>
    # tag, but the browser registers them on the Window. The following is the
    # complete list of such event handlers as defined by the draft HTML5 
    # specification:
    #
    # onafterprint      onfocus         ononline        onresize
    # onbeforeprint     onhashchange    onpagehide      onstorage
    # onbeforeunload    onload          onpageshow      onundo
    # onblur            onmessage       onpopstate      onunload
    # onerror           onoffline       onredo
    window_events = ('afterprint',
                     'beforeprint',
                     'beforeunload',
                     'blur',
                     'error',
                     'focus',
                     'hashchange',
                     'load',
                     'message',
                     'offline',
                     'online',
                     'pagehide',
                     'pageshow',
                     'popstate',
                     'redo',
                     'resize',
                     'storage',
                     'undo',
                     'unload')

    window_on_events = ['on' + e for e in window_events]

    window_storage_events = ('storage', )
    window_on_storage_events = ['on' + e for e in window_storage_events]


    def __init__(self, window):
        self.window            = window
        self.window.doc.DFT    = self
        self.anchors           = list()
        self.meta              = dict()
        self._context          = None
        log.DFT                = self
        self._init_events()

        PyV8.JSEngine.setStackLimit(10 * 1024 * 1024)
   
    def _init_events(self):
        self.listeners = list()

        # Events are handled in the same order they are inserted in this list
        self.handled_events = ['load', 'mousemove']

        for event in log.ThugOpts.events:
            self.handled_events.append(event)

        log.debug("Handling DOM Events: %s", ",".join(self.handled_events))
        self.handled_on_events = ['on' + e for e in self.handled_events]
        self.dispatched_events = set()

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        pass

    @property
    def context(self):
        if self._context is None:
            self._context = self.window.context

        return self._context

    def build_shellcode(self, s):
        i  = 0
        sc = list()

        while i < len(s):
            if s[i] == '"':
                i += 1
                continue

            if s[i] == '%':
                if (i + 6) <= len(s) and s[i + 1] == 'u':
                    currchar = int(s[i + 2: i + 4], 16)
                    nextchar = int(s[i + 4: i + 6], 16)
                    sc.append(chr(nextchar))
                    sc.append(chr(currchar))
                    i += 6
                elif (i + 3) <= len(s) and s[i + 1] == 'u':
                    currchar = int(s[i + 2: i + 4], 16)
                    sc.append(chr(currchar))
                    i += 3
                else:
                    sc.append(s[i])
                    i += 1
            else:
                sc.append(s[i])
                i += 1

        return ''.join(sc)

    def check_URLDownloadToFile(self, emu):
        profile = emu.emu_profile_output

        while True:
            offset = profile.find('URLDownloadToFile')
            if offset < 0:
                break

            profile = profile[offset:]

            p = profile.split(';')
            if len(p) < 2:
                profile = profile[1:]
                continue
            
            p = p[1].split('"')
            if len(p) < 3:
                profile = profile[1:]
                continue

            url = p[1]
            if url in log.ThugLogging.shellcode_urls:
                return

            try:
                if self.window._navigator.fetch(url, redirect_type = "URLDownloadToFile") is None:
                    log.ThugLogging.add_behavior_warn('[URLDownloadToFile] Fetch failed')

                log.ThugLogging.shellcode_urls.add(url)
            except: #pylint:disable=bare-except
                log.ThugLogging.add_behavior_warn('[URLDownloadToFile] Fetch failed')

            profile = profile[1:]

    def check_WinExec(self, emu):
        profile = emu.emu_profile_output

        while True:
            offset = profile.find('WinExec')
            if offset < 0:
                break

            profile = profile[offset:]

            p = profile.split(';')
            if not p:
                profile = profile[1:]
                continue

            s = p[0].split('"')
            if len(s) < 2:
                profile = profile[1:]
                continue

            url = s[1]
            if not url.startswith("http"):
                profile = profile[1:]
                continue

            if url in log.ThugLogging.shellcode_urls:
                return

            try:
                if self.window._navigator.fetch(url, redirect_type = "WinExec") is None:
                    log.ThugLogging.add_behavior_warn('[WinExec] Fetch failed')

                log.ThugLogging.shellcode_urls.add(url)
            except: #pylint:disable=bare-except
                log.ThugLogging.add_behavior_warn('[WinExec] Fetch failed')

            profile = profile[1:]

    def check_shellcode(self, shellcode):
        try:
            sc = self.build_shellcode(shellcode)
        except: #pylint:disable=bare-except
            sc = shellcode

        emu = pylibemu.Emulator(enable_hooks = False)
        emu.run(sc)
        
        if emu.emu_profile_output:
            log.ThugLogging.add_code_snippet(emu.emu_profile_output, 'Assembly', 'Shellcode', method = 'Static Analysis')
            log.warning("[Shellcode Profile]\n\n%s", emu.emu_profile_output)
            self.check_URLDownloadToFile(emu)
            self.check_WinExec(emu)

        self.check_url(sc, shellcode)
        emu.free()

    def check_url(self, sc, shellcode):
        schemes = []
        for scheme in ('http://', 'https://'):
            if scheme in sc:
                schemes.append(scheme)

        for scheme in schemes:
            offset = sc.find(scheme)
            if offset == -1:
                continue

            url = sc[offset:]
            url = url.split()[0]
            if url.endswith("'") or url.endswith('"'):
                url = url[:-1]
            
            if len(url) == 0:
                continue

            i = 0

            while i < len(url):
                if not url[i] in string.printable:
                    break
                i += 1

            url = url[:i]

            log.ThugLogging.add_code_snippet(shellcode, 'Assembly', 'Shellcode', method = 'Static Analysis')
            log.ThugLogging.add_behavior_warn(description = '[Shellcode Analysis] URL Detected: %s' % (url, ), method = 'Static Analysis')

            if url in log.ThugLogging.shellcode_urls:
                return

            try:
                self.window._navigator.fetch(url, redirect_type = "URL found")
                log.ThugLogging.shellcode_urls.add(url)
            except: #pylint:disable=bare-except
                pass

    def check_shellcodes(self):
        while True:
            try:
                shellcode = log.ThugLogging.shellcodes.pop()
                self.check_shellcode(shellcode)
            except KeyError:
                break

    def check_attrs(self, p):
        for value in p.attrs.values():
            self.check_shellcode(value)
        
    def shift(self, script, s):
        if script.lower().startswith(s):
            return script[len(s):].lstrip()
        return script

    def fix(self, script):
        script = self.shift(script, 'javascript:')
        script = self.shift(script, 'return')
        return script

    def get_evtObject(self, elem, evtType):
        evtObject = None

        if evtType in MouseEvent.MouseEventTypes:
            evtObject = MouseEvent(evtType, elem)

        if evtType in HTMLEvent.HTMLEventTypes:
            evtObject = HTMLEvent(evtType, elem)

        if evtObject is None:
            return None

        evtObject.eventPhase = Event.AT_TARGET
        evtObject.currentTarget = elem
        return evtObject

    # Events handling
    def handle_element_event(self, evt):
        for (elem, eventType, listener, capture) in self.listeners: #pylint:disable=unused-variable
            if getattr(elem, 'name', None) is None:
                continue

            if elem.name in ('body', ):
                continue

            if eventType in (evt, ):
                if (elem._node, evt) in self.dispatched_events:
                    continue
            
                elem._node.dispatchEvent(evt)
                self.dispatched_events.add((elem._node, evt))

    def handle_window_storage_event(self, onevt, evtObject):
        if onevt in self.handled_on_events:
            handler = getattr(self.window, onevt, None)
            if handler:
                handler(evtObject)

    def handle_window_event(self, onevt):
        if onevt in self.handled_on_events and onevt not in self.window_on_storage_events:
            handler = getattr(self.window, onevt, None)
            if handler:
                evtObject = self.get_evtObject(self.window, onevt[2:])
                if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
                    self.window.event = evtObject
                    handler()
                else:
                    handler(evtObject)

    def handle_document_event(self, onevt):
        if onevt in self.handled_on_events:
            handler = getattr(self.window.doc, onevt, None)
            if handler:
                evtObject = self.get_evtObject(self.window.doc, onevt[2:])
                if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
                    self.window.event = evtObject
                    handler()
                else:
                    handler(evtObject)

        #if not getattr(self.window.doc.tag, '_listeners', None):
        #    return

        if '_listeners' not in self.window.doc.tag.__dict__:
            return

        for (eventType, listener, capture) in self.window.doc.tag._listeners: #pylint:disable=unused-variable
            if eventType not in (onevt[2:], ):
                continue
                
            evtObject = self.get_evtObject(self.window.doc, eventType)
            if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
                self.window.event = evtObject
                listener()
            else:
                listener(evtObject)

    def build_event_handler(self, ctx, h):
        # When an event handler is registered by setting an HTML attribute
        # the browser converts the string of JavaScript code into a function.
        # Browsers other than IE construct a function with a single argument
        # named `event'. IE constructs a function that expects no argument.
        # If the identifier `event' is used in such a function, it refers to
        # `window.event'. In either case, HTML event handlers can refer to 
        # the event object as `event'.
        if log.ThugOpts.Personality.isIE():
            return ctx.eval("(function() { with(document) { with(this.form || {}) { with(this) { event = window.event; %s } } } }) " % (h, ))

        return ctx.eval("(function(event) { with(document) { with(this.form || {}) { with(this) { %s } } } }) " % (h, ))

    def set_event_handler_attributes(self, elem):
        try:
            attrs = elem.attrs
        except: #pylint:disable=bare-except
            return
       
        if 'language' in list(attrs.keys()) and not attrs['language'].lower() in ('javascript', ):
            return

        for evt, h in attrs.items():
            if evt not in self.handled_on_events:
                continue

            self.attach_event(elem, evt, h)

    def attach_event(self, elem, evt, h):
        handler = None

        if isinstance(h, six.string_types):
            handler = self.build_event_handler(self.context, h)
            #PyV8.JSEngine.collect()
        elif isinstance(h, PyV8.JSFunction):
            handler = h
        else:
            try:
                handler = getattr(self.context.locals, h, None)
            except: #pylint:disable=bare-except
                pass

        if not handler:
            return

        if getattr(elem, 'name', None) and elem.name in ('body', ) and evt in self.window_on_events:
            setattr(self.window, evt, handler)
            return

        if not getattr(elem, '_node', None):
            DOMImplementation.createHTMLElement(self.window.doc, elem)
            
        elem._node._attachEvent(evt, handler, True)

    def set_event_listeners(self, elem):
        p = getattr(elem, '_node', None)

        if p:
            for evt in self.handled_on_events:
                h = getattr(p, evt, None)
                if h:
                    self.attach_event(elem, evt, h)
            
        listeners = getattr(elem, '_listeners', None)
        if listeners:
            for (eventType, listener, capture) in listeners:
                if eventType in self.handled_events:
                    self.listeners.append((elem, eventType, listener, capture))

    @property
    def javaUserAgent(self):
        javaplugin = log.ThugVulnModules._javaplugin.split('.')
        last = javaplugin.pop()
        version =  '%s_%s' % ('.'.join(javaplugin), last)
        return log.ThugOpts.Personality.javaUserAgent % (version, )

    @property
    def javaWebStartUserAgent(self):
        javaplugin = log.ThugVulnModules._javaplugin.split('.')
        last = javaplugin.pop()
        version =  '%s_%s' % ('.'.join(javaplugin), last)
        return "JNLP/6.0 javaws/%s (b04) Java/%s" % (version, version, )

    @property
    def shockwaveFlash(self):
        return ','.join(log.ThugVulnModules.shockwave_flash.split('.'))

    def _check_jnlp_param(self, param):
        name  = param.attrs['name']
        value = param.attrs['value']

        if name in ('__applet_ssv_validated', ) and value.lower() in ('true', ):
            log.ThugLogging.log_exploit_event(self.window.url,
                                              'Java WebStart',
                                              'Java Security Warning Bypass (CVE-2013-2423)',
                                              cve = 'CVE-2013-2423')

    def _handle_jnlp(self, data, headers, params):
        try:
            soup = BeautifulSoup.BeautifulSoup(data, "lxml")
        except: #pylint:disable=bare-except
            return

        jnlp = soup.find("jnlp")
        if jnlp is None:
            return

        codebase = jnlp.attrs['codebase'] if 'codebase' in jnlp.attrs else ''

        log.ThugLogging.add_behavior_warn(description = '[JNLP Detected]', method = 'Dynamic Analysis')

        for param in soup.find_all('param'):
            log.ThugLogging.add_behavior_warn(description = '[JNLP] %s' % (param, ), method = 'Dynamic Analysis')
            self._check_jnlp_param(param)

        jars = soup.find_all("jar")
        if not jars:
            return

        headers['User-Agent'] = self.javaWebStartUserAgent

        for jar in jars:
            try:
                url = "%s%s" % (codebase, jar.attrs['href'], )
                self.window._navigator.fetch(url, headers = headers, redirect_type = "JNLP", params = params)
            except: #pylint:disable=bare-except
                pass

    def do_handle_params(self, _object):
        params = dict()

        for child in _object.find_all():
            name = getattr(child, 'name', None)
            if name is None:
                continue

            if name.lower() in ('param', ):
                if all(p in child.attrs for p in ('name', 'value', )):
                    params[child.attrs['name'].lower()] = child.attrs['value']

            if name.lower() in ('embed', ):
                self.handle_embed(child)

        if not params:
            return params

        headers = dict()
        headers['Connection'] = 'keep-alive'

        if 'type' in params:
            headers['Content-Type'] = params['type']
        else:
            name = getattr(_object, 'name', None)

            if name in ('applet', ) or 'archive' in params:
                headers['Content-Type'] = 'application/x-java-archive'

            if 'movie' in params:
                headers['x-flash-version'] = self.shockwaveFlash

        if 'Content-Type' in headers and 'java' in headers['Content-Type'] and log.ThugOpts.Personality.javaUserAgent:
            headers['User-Agent'] = self.javaUserAgent

        for key in ('filename', 'movie', ):
            if key not in params:
                continue

            try:
                self.window._navigator.fetch(params[key],
                                             headers = headers,
                                             redirect_type = "params",
                                             params = params)
            except: #pylint:disable=bare-except
                pass

        for key, value in params.items():
            if key in ('filename', 'movie', 'archive', 'code', 'codebase', 'source', ):
                continue

            if key.lower() not in ('jnlp_href', ) and not value.startswith('http'):
                continue

            try:
                response = self.window._navigator.fetch(value,
                                                        headers = headers,
                                                        redirect_type = "params",
                                                        params = params)

                if response:
                    self._handle_jnlp(response.content, headers, params)
            except: #pylint:disable=bare-except
                pass

        if 'source' in params:
            try:
                self.window._navigator.fetch(params['source'],
                                             headers = headers,
                                             redirect_type = "params",
                                             params = params)
            except: #pylint:disable=bare-except
                pass

        if 'archive' not in params and 'code' not in params:
            return params

        if 'codebase' in params:
            archive = urlparse.urljoin(params['codebase'], params['archive'])
        else:
            archive = params['archive']

        try:
            self.window._navigator.fetch(archive,
                                         headers = headers,
                                         redirect_type = "params",
                                         params = params)
        except: #pylint:disable=bare-except
            pass

        return params

    def handle_object(self, _object):
        log.warning(_object)

        #self.check_attrs(_object)
        params = self.do_handle_params(_object)

        classid  = _object.get('classid', None)
        _id      = _object.get('id', None)
        codebase = _object.get('codebase', None)
        data     = _object.get('data', None)

        if codebase:
            try:
                self.window._navigator.fetch(codebase,
                                             redirect_type = "object codebase",
                                             params = params)
            except: #pylint:disable=bare-except
                pass

        if data and not data.startswith('data:'):
            try:
                self.window._navigator.fetch(data,
                                             redirect_type = "object data",
                                             params = params)
            except: #pylint:disable=bare-except
                pass

        if not log.ThugOpts.Personality.isIE():
            return

        #if classid and _id:
        if classid:
            try:
                axo = _ActiveXObject(self.window, classid, 'id')
            except TypeError:
                return

            if _id is None:
                return

            setattr(self.window, _id, axo)
            setattr(self.window.doc, _id, axo)

    def _get_script_for_event_params(self, attr_event):
        params = attr_event.split('(')
        if len(params) < 2:
            return None

        params = params[1].split(')')[0]
        return params.split(',')

    def _handle_script_for_event(self, script):
        attr_for   = script.get("for", None)
        attr_event = script.get("event", None)

        if not attr_for or not attr_event:
            return

        params = self._get_script_for_event_params(attr_event)
        if not params:
            return

        if 'playstatechange' in attr_event.lower():
            with self.context as ctx:
                newState = params.pop()
                ctx.eval("%s = 0;" % (newState.strip(), ))
                try:
                    oldState = params.pop()
                    ctx.eval("%s = 3;" % (oldState.strip(), ))
                except: #pylint:disable=bare-except
                    pass

    def handle_script(self, script):
        language = script.get('language', 'javascript').lower()
        if 'javascript' in language:
            language = 'javascript'

        handler = getattr(self, "handle_%s" % (language, ), None)

        if not handler:
            log.warning("Unhandled script language: %s", language)
            return

        if log.ThugOpts.Personality.isIE():
            self._handle_script_for_event(script)

        handler(script)

    def handle_external_javascript_text(self, s, response):
        js = response.content

        # First attempt
        # No specified encoding. This attempt succeeds most of the times.
        try:
            s.text = js
            return True
        except: #pylint:disable=bare-except
            pass

        # Second attempt
        # Requests will automatically decode content from the server. Most
        # unicode charsets are seamlessly decoded. When you make a request,
        # Requests makes educated guesses about the encoding of the response
        # based on the HTTP headers.
        if response.encoding:
            s.text = response.text
            return True

        # Third (and last) attempt
        # The encoding is (hopefully) detected through the Encoding class.
        enc = log.Encoding.detect(js)
        if enc['encoding'] is None:
            return False

        s.text = js.decode(enc['encoding'])
        return True

    def handle_external_javascript(self, script):
        src = script.get('src', None)
        if src is None:
            return

        try:
            response = self.window._navigator.fetch(src, redirect_type = "script src")
        except: #pylint:disable=bare-except
            return

        if response is None:
            return

        if response.status_code == 404:
            return

        if not len(response.content):
            return

        log.ThugLogging.add_code_snippet(response.content, 'Javascript', 'External')

        s = self.window.doc.createElement('script')

        for attr in script.attrs:
            if attr.lower() not in ('src', ):
                s.setAttribute(attr, script.get(attr))

        if not self.handle_external_javascript_text(s, response):
            return

        try:
            body = self.window.doc.body
        except: #pylint:disable=bare-except
            body = self.window.doc.getElementsByTagName('body')[0]

        if body:
            body.appendChild(s)

        self.window.evalScript(response.content, tag = script)

    def handle_javascript(self, script):
        try:
            log.info(jsbeautifier.beautify(str(script)))
        except: #pylint:disable=bare-except
            log.info(script)

        self.handle_external_javascript(script)

        js = getattr(script, 'text', None)

        if js:
            log.ThugLogging.add_code_snippet(js, 'Javascript', 'Contained_Inside')
            self.window.evalScript(js, tag = script)

        self.check_shellcodes()
        self.check_anchors()

    def handle_vbscript(self, script):
        log.info(script)
        log.ThugLogging.add_code_snippet(str(script), 'VBScript', 'Contained_Inside')
        log.warning("VBScript parsing not available")

    def handle_vbs(self, script):
        self.handle_vbscript(script)

    def handle_visualbasic(self, script):
        self.handle_vbscript(script)

    def handle_noscript(self, script):
        pass

    def handle_param(self, param):
        log.info(param)

        #name  = param.get('name' , None)
        #value = param.get('value', None)

    def handle_embed(self, embed):
        log.warning(embed)

        src = embed.get('src', None)
        if src is None:
            return

        headers = dict()

        embed_type = embed.get('type', None)
        if embed_type:
            headers['Content-Type'] = embed_type

        if 'Content-Type' in headers:
            if 'java' in headers['Content-Type'] and log.ThugOpts.Personality.javaUserAgent: 
                headers['User-Agent'] = self.javaUserAgent

            if 'shockwave-flash' in headers['Content-Type']:
                headers['x-flash-version']  = self.shockwaveFlash

        try:
            self.window._navigator.fetch(src, headers = headers, redirect_type = "embed")
        except: #pylint:disable=bare-except
            pass

    def handle_applet(self, applet):
        log.warning(applet)

        params = self.do_handle_params(applet)

        archive = applet.get('archive', None)
        if not archive:
            return

        headers = dict()
        headers['Connection']   = 'keep-alive'
        headers['Content-type'] = 'application/x-java-archive'

        if log.ThugOpts.Personality.javaUserAgent:
            headers['User-Agent'] = self.javaUserAgent

        try:
            self.window._navigator.fetch(archive,
                                         headers = headers,
                                         redirect_type = "applet",
                                         params = params)
        except: #pylint:disable=bare-except
            pass

    def handle_meta(self, meta):
        log.info(meta)

        name = meta.get('name', None)
        if name and name.lower() in ('generator', ):
            content = meta.get('content', None)
            if content:
                log.ThugLogging.add_behavior_warn("[Meta] Generator: %s" % (content, ))

        self.handle_meta_http_equiv(meta)

    def handle_meta_http_equiv(self, meta):
        http_equiv = meta.get('http-equiv', None)
        if http_equiv is None:
            return

        content = meta.get('content', None)
        if content is None:
            return

        tag = http_equiv.lower().replace('-', '_')
        handler = getattr(self, 'handle_meta_%s' % (tag, ), None)
        if handler:
            handler(http_equiv, content)

    def handle_meta_x_ua_compatible(self, http_equiv, content):
        # Internet Explorer < 8.0 doesn't support the X-UA-Compatible header
        # and the webpage doesn't specify a <!DOCTYPE> directive.
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion >= 8:
            if http_equiv.lower() in ('x-ua-compatible'):
                self.window.doc.compatible = content

    def force_handle_meta_x_ua_compatible(self):
        for meta in self.window.doc.doc.find_all('meta'):
            http_equiv = meta.get('http-equiv', None)
            if http_equiv is None:
                continue

            if not http_equiv.lower() in ('x-ua-compatible', ):
                continue

            content = meta.get('content', None)
            if content is None:
                continue

            self.handle_meta_x_ua_compatible(http_equiv, content)

    def handle_meta_refresh(self, http_equiv, content):
        from .Window import Window

        if http_equiv.lower() != 'refresh':
            return

        if 'url' not in content.lower():
            return

        timeout = 0 #pylint:disable=unused-variable
        url     = None

        for s in content.split(';'):
            s = s.strip()
            if s.lower().startswith('url='):
                url = s[4:]
            try:
                timeout = int(s)
            except: #pylint:disable=bare-except
                pass

        if not url:
            return

        if url.startswith("'") and url.endswith("'"):
            url = url[1:-1]

        if url in self.meta and self.meta[url] >= 3:
            return

        try:
            response = self.window._navigator.fetch(url, redirect_type = "meta")
        except: #pylint:disable=bare-except
            return

        if response is None:
            return

        if response.status_code == 404:
            return

        if url in self.meta:
            self.meta[url] += 1
        else:
            self.meta[url] = 1

        #self.window.doc     = w3c.parseString(content)
        #self.window.doc.DFT = self
        #self.window.open(url)
        #self.run()

        doc    = w3c.parseString(response.content)
        window = Window(self.window.url, doc, personality = log.ThugOpts.useragent)
        window.open(url)

        dft = DFT(window)
        dft.run()

    def handle_frame(self, frame, redirect_type = 'frame'):
        from .Window import Window

        log.warning(frame)
        
        src = frame.get('src', None)
        if not src:
            return 

        try:
            response = self.window._navigator.fetch(src, redirect_type = redirect_type)
        except: #pylint:disable=bare-except
            return

        if response is None:
            return

        if response.status_code == 404:
            return

        ctype = response.headers.get('content-type', None)
        if ctype:
            handler = log.MIMEHandler.get_handler(ctype)
            if handler and handler(src, response.content):
                return

        _src = log.HTTPSession.normalize_url(self.window, src)
        if _src:
            src = _src

        doc    = w3c.parseString(response.content)
        window = Window(self.window.url, doc, personality = log.ThugOpts.useragent)
        window.open(src)

        frame_id = frame.get('id', None)
        if frame_id:
            log.ThugLogging.windows[frame_id] = window

        dft = DFT(window)
        dft.run()

    def handle_iframe(self, iframe):
        self.handle_frame(iframe, 'iframe')

    def handle_body(self, body):
        pass

    def do_handle_font_face_rule(self, rule):
        for p in rule.style:
            if p.name.lower() not in ('src', ):
                continue

            url = p.value
            if url.startswith('url(') and len(url) > 4:
                url = url.split('url(')[1].split(')')[0]

            try:
                self.window._navigator.fetch(url, redirect_type = "font face")
            except: #pylint:disable=bare-except
                return

    def handle_style(self, style):
        log.info(style)

        cssparser = CSSParser(loglevel = logging.CRITICAL, validate = False)

        try:
            sheet = cssparser.parseString(style.text)
        except: #pylint:disable=bare-except
            return

        for rule in sheet:
            if rule.type == rule.FONT_FACE_RULE:
                self.do_handle_font_face_rule(rule)

    def _handle_data_uri(self, href):
        """
        Data URI Scheme
        data:[<MIME-type>][;charset=<encoding>][;base64],<data>

        The encoding is indicated by ;base64. If it is present the data is
        encoded as base64. Without it the data (as a sequence of octets) is
        represented using ASCII encoding for octets inside the range of safe
        URL characters and using the standard %xx hex encoding of URLs for
        octets outside that range. If <MIME-type> is omitted, it defaults to
        text/plain;charset=US-ASCII. (As a shorthand, the type can be omitted
        but the charset parameter supplied.)

        Some browsers (Chrome, Opera, Safari, Firefox) accept a non-standard
        ordering if both ;base64 and ;charset are supplied, while Internet
        Explorer requires that the charset's specification must precede the
        base64 token.
        """
        if not href.lower().startswith("data:"):
            return False

        h = href.split(",")
        if len(h) < 2:
            return False

        data = h[1]
        opts = h[0][len("data:"):].split(";")

        if 'base64' in opts:
            data = base64.b64decode(h[1])
            opts.remove('base64')

        if not opts:
            opts = ["text/plain", "charset=US-ASCII"]

        mimetype = opts[0]
        handler  = log.MIMEHandler.get_handler(mimetype)

        if handler:
            handler(self.window.url, data)
            return True

        return False

    def handle_a(self, anchor):
        log.info(anchor)

        if log.ThugOpts.extensive:
            log.info(anchor)

            href = anchor.get('href', None)
            if not href:
                return

            if self._handle_data_uri(href):
                return

            try:
                response = self.window._navigator.fetch(href, redirect_type = "anchor")
            except: #pylint:disable=bare-except
                return

            if response is None:
                return

            if response.status_code == 404:
                return

        self.anchors.append(anchor)

    def handle_link(self, link):
        log.info(link)

        href = link.get('href', None)
        if not href:
            return

        if self._handle_data_uri(href):
            return

        try:
            response = self.window._navigator.fetch(href, redirect_type = "link")
        except: #pylint:disable=bare-except
            return

        if response is None:
            return

        if response.status_code == 404:
            return

    def check_anchors(self):
        clicked_anchors = [a for a in self.anchors if '_clicked' in a.attrs]
        if not clicked_anchors:
            return

        clicked_anchors.sort(key = lambda anchor: anchor['_clicked'])
        
        for anchor in clicked_anchors:
            href = anchor['href']
            del anchor['_clicked']
            
            if 'target' in anchor.attrs and not anchor.attrs['target'] in ('_self', ):
                pid = os.fork()
                if pid == 0:
                    self.follow_href(href)
                else:
                    os.waitpid(pid, 0)
            else:
                self.follow_href(href)

    def follow_href(self, href):
        from .Window import Window

        doc    = w3c.parseString('')
        window = Window(self.window.url, doc, personality = log.ThugOpts.useragent)
        window = window.open(href)
            
        if window:
            dft = DFT(window)
            dft.run()

    def do_handle(self, child, skip = True):
        name = getattr(child, "name", None)

        if name is None:
            return False

        if skip and name in ('object', 'applet', ):
            return False

        # FIXME: this workaround should be not necessary once the Python 3
        # porting will be completed.
        handler = None

        try:
            handler = getattr(self, "handle_%s" % (str(name.lower()), ), None)
        except:
            try:
                handler = getattr(self, "handle_%s" % (name.encode('utf-8', 'replace'),  ), None)
            except:
                pass

        if handler:
            handler(child)
            return True

        return False

    def _run(self, soup = None):
        log.debug(self.window.doc)
        
        if soup is None:
            soup = self.window.doc.doc
    
        _soup = soup

        # Dirty hack
        for p in soup.find_all('object'):
            self.handle_object(p)

        for p in soup.find_all('applet'):
            self.handle_applet(p)

        for child in soup.descendants:
            self.set_event_handler_attributes(child)
            if not self.do_handle(child):
                continue

            analyzed = set()
            recur    = True

            while recur:
                recur = False
                
                if tuple(soup.descendants) == tuple(_soup.descendants):
                    break
                
                for _child in set(soup.descendants) - set(_soup.descendants): 
                    if _child not in analyzed:
                        analyzed.add(_child)
                        recur = True

                        name  = getattr(_child, "name", None)
                        if name:
                            self.do_handle(_child, False)
            
            analyzed.clear()
            _soup = soup

        self.window.doc._readyState = "complete"

        for child in soup.descendants:
            self.set_event_listeners(child)

        for evt in self.handled_on_events:
            try:
                self.handle_window_event(evt)
            except: #pylint:disable=bare-except
                log.warning("[handle_window_event] Event %s not properly handled", evt)

        for evt in self.handled_on_events:
            try:
                self.handle_document_event(evt)
            except: #pylint:disable=bare-except
                log.warning("[handle_document_event] Event %s not properly handled", evt)

        for evt in self.handled_events:
            try:
                self.handle_element_event(evt)
            except: #pylint:disable=bare-except
                log.warning("[handle_element_event] Event %s not properly handled", evt)

    def run(self):
        with self.context as ctx: #pylint:disable=unused-variable
            self._run()
            self.check_shellcodes()
