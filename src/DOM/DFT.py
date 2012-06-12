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
import struct
import W3C.w3c as w3c
import hashlib
import logging
import Window
import PyV8
import jsbeautifier
import bs4 as BeautifulSoup
from W3C.DOMImplementation import DOMImplementation
from ActiveX.ActiveX import _ActiveXObject

log        = logging.getLogger("Thug")
vbs_parser = True
    
try:
    #from vb2py.vbparser import convertVBtoPython, VBCodeModule
    import pyjs
except ImportError:
    vbs_parser = False
    pass
    
class DFT(object):
    javascript     = ('javascript', )
    vbscript       = ('vbs', 'vbscript', 'visualbasic')

    # Events are handled in the same order they are inserted in this list
    handled_events = ('load',
                      'mousemove',
                      'click'
                      )

    handled_on_events = map(lambda e: 'on' + e, handled_events)
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

    window_on_events = map(lambda e: 'on' + e, window_events)
                      
    def __init__(self, window):
        self.window            = window
        self.window.doc.DFT    = self
        self.meta              = dict()
        self.listeners         = list()
        self.dispatched_events = set()
    
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def check_shellcode(self, s):
        try:
            shellcode = s.decode('utf-8')
        except:
            shellcode = s

        sc = b''
        try:
            for c in shellcode:
                sc += struct.pack('<H', ord(c))
        except:
            sc = shellcode

        if not sc:
            return

        emu = pylibemu.Emulator()
        emu.run(sc)
        if emu.emu_profile_output:
            log.warning(emu.emu_profile_output)

        emu.free()

    def check_attrs(self, p):
        for attr, value in p.attrs.items():
            self.check_shellcode(value)
        
    def shift(self, script, s):
        if script.lower().startswith(s):
            return script[len(s):].lstrip()
        return script

    def fix(self, script):
        script = self.shift(script, 'javascript:')
        script = self.shift(script, 'return')
        return script

    def _fetch(self, url):
        try:
            response, content = self.window._navigator.fetch(url)
        except:
            return

        if response.status == 404:
            return

        m = hashlib.md5()
        m.update(content)
        h = m.hexdigest()

        log.warning('Saving remote content at %s (MD5: %s)' % (url, h, ))
        with open(os.path.join(log.baseDir, h), 'wb') as fd:
            fd.write(content)

    # Events handling
    def handle_element_event(self, evt):
        for (elem, eventType, listener, capture) in self.listeners:
            if elem.name in ('body', ):
                continue

            if eventType in (evt, ):
                if (elem._node, evt) in self.dispatched_events:
                    continue
                elem._node.dispatchEvent(evt)
                self.dispatched_events.add((elem._node, evt))

    def handle_window_event(self, onevt):
        if onevt in self.handled_on_events:
            handler = getattr(self.window, onevt, None)
            if handler:
                with self.window.context as ctx:
                    handler()

    def handle_document_event(self, onevt):
        if onevt in self.handled_on_events: 
            handler = getattr(self.window.doc, onevt, None)
            if handler:
                with self.window.context as ctx:
                    handler()

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
        except:
            return

        # FIXME
        if 'language' in attrs.keys() and attrs['language'].lower() is not 'javascript':
            return

        for evt, h in attrs.items():
            if evt not in self.handled_on_events:
                continue

            self.attach_event(elem, evt, h)

    def attach_event(self, elem, evt, h):
        with self.window.context as ctx:
            handler = None
            
            if isinstance(h, basestring):
                handler = self.build_event_handler(ctx, h)
            elif isinstance(h, PyV8.JSFunction):
                handler = h
            else:
                try:
                    handler = getattr(ctx.locals, h, None)
                except:
                    pass

            if not handler:
                return

            if elem.name in ('body', ) and evt in self.window_on_events:
                setattr(self.window, evt, handler)
                return

            if not getattr(elem, '_node', None):
                DOMImplementation.createHTMLElement(self.window.doc, elem)
            
            elem._node._attachEvent(evt, handler, True)

            #try:
            #    elem._node._attachEvent(evt, handler)
            #except:
            #    DOMImplementation.createHTMLElement(self.window.doc, elem)
            #    elem._node._attachEvent(evt, handler)

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

    def handle_object(self, object):
        log.warning(object)

        self.check_attrs(object)
                
        classid = object.get('classid', None)
        id      = object.get('id', None)

        if classid and id:
            setattr(self.window, id, _ActiveXObject(self.window, classid, 'id'))

    def handle_script(self, script):
        language = script.get('language', 'javascript').lower()
        handler  = getattr(self, "handle_%s" % (language, ), None)

        if not handler:
            log.warning("Unhandled script language: %s" % (language, ))
            return

        handler(script)
            
    def handle_javascript(self, script):
        try:
            log.info(jsbeautifier.beautify(str(script)))
        except:
            log.info(script)

        js = getattr(script, 'text', None)
        relationship = 'Contained_Inside'

        if not js:
            src = script.get('src', None)
            if not src:
                return
        
            try:
                response, js = self.window._navigator.fetch(src)
            except:
                return
                
            if response.status == 404:
                return

            relationship = 'External'

        if len(js):
            log.ThugLogging.add_code_snippet(js, 'Javascript', relationship)

        self.window.evalScript(js, tag = script)

    def handle_vbscript(self, script):
        log.info(script)
        log.ThugLogging.add_code_snippet(str(script), 'VBScript', 'Contained_Inside')

        if not vbs_parser:
            log.warning("VBScript parsing not enabled (vb2py is needed)")
            return

        vbs_py = convertVBtoPython(script.string, container = VBCodeModule())
        log.warning(vbs_py)

        #pyjs_js = os.path.join(os.path.dirname(__file__), 'py.js')
        #self.window.evalScript(open(pyjs_js, 'r').read())

        #vbs_js = pyjs.compile(vbs_py)
        #print vbs_js
        #self.window.evalScript(vbs_js)

    def handle_vbs(self, script):
        self.handle_vbscript(script)

    def handle_visualbasic(self, script):
        self.handle_vbscript(script)

    def handle_noscript(self, script):
        pass

    def handle_param(self, param):
        log.warning(param)

        name  = param.get('name' , None)
        value = param.get('value', None)

        if name in ('movie', ):
            self._fetch(value)

        if 'http' not in value:
            return

        urls = [p for p in value.split() if p.startswith('http')]
        for url in urls:
            self._fetch(url)

    def handle_embed(self, embed):
        log.warning(embed)

        src = embed.get('src', None)
        if src:
            self._fetch(src)

    def handle_applet(self, applet):
        log.warning(applet)

        archive = applet.get('archive', None)
        if not archive:
            return

        try:
            response, content = self.window._navigator.fetch(archive)
        except:
            return

        if response.status == 404:
            return

        log.warning('Saving applet %s' % (archive, ))
        
        with open(os.path.join(log.baseDir, archive.split('/')[-1]), 'wb') as fd:
            fd.write(content)

    def handle_meta(self, meta):
        log.warning(meta)

        name = meta.get('name', None)
        if name and name.lower() in ('generator', ):
            content = meta.get('content', None)
            if content:
                log.ThugLogging.add_behavior_warn("[Meta] Generator: %s" % (content, ))

        http_equiv = meta.get('http-equiv', None)
        if not http_equiv or http_equiv.lower() != 'refresh':
            return

        content = meta.get('content', None)
        if not content or not 'url' in content.lower():
            return

        timeout = 0
        url     = None

        for s in content.split(';'):
            s = s.strip()
            if s.lower().startswith('url='):
                url = s[4:]
            try:
                timeout = int(s)
            except:
                pass

        if not url:
            return

        if url in self.meta and self.meta[url] >= 3:
            return

        try:
            response, content = self.window._navigator.fetch(url)
        except:
            return

        if response.status == 404:
            return

        if url in self.meta:
            self.meta[url] += 1
        else:
            self.meta[url] = 1

        self.window.doc     = w3c.parseString(content)
        self.window.doc.DFT = self
        self.window.open(url)
        self.run()

    def handle_frame(self, frame, redirect_type = 'frame'):
        log.warning(frame)
        
        src = frame.get('src', None)
        if not src:
            return 

        try:
            response, content = self.window._navigator.fetch(src, redirect_type)
        except:
            return

        if response.status == 404:
            return

        if 'content-type' in response and response['content-type'] in ('application/pdf', ):
            return

        doc    = w3c.parseString(content)
        window = Window.Window(src, doc)
        window.open(src)
            
        dft = DFT(window)
        dft.run()

    def handle_iframe(self, iframe):
        self.handle_frame(iframe, 'iframe')

    def handle_body(self, body):
        pass

    def run(self):
        log.debug(self.window.doc)
        
        soup = self.window.doc.doc
        # Dirty hack
        for p in soup.find_all('object'):
            self.handle_object(p)

        for child in soup.descendants:
            self.set_event_handler_attributes(child)

            name = getattr(child, "name", None)
            if name is None or name in ('object', ):
                continue

            handler = getattr(self, "handle_%s" % (name, ), None)
            if handler:
                handler(child)

        for child in soup.descendants:
            self.set_event_listeners(child)

        for evt in self.handled_on_events:
            self.handle_window_event(evt)

        for evt in self.handled_on_events:
            self.handle_document_event(evt)

        for evt in self.handled_events:
            self.handle_element_event(evt)
