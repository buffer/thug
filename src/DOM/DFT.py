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
import W3C.w3c as w3c
import hashlib
import logging
import Window
from ActiveX.ActiveX import _ActiveXObject

log        = logging.getLogger("Thug.DOM.DFT")
vbs_parser = True

try:
    #from vb2py.vbparser import convertVBtoPython, VBCodeModule
    import pyjs
except ImportError:
    vbs_parser = False
    pass
    
class DFT(object):
    javascript = ('javascript', )
    vbscript   = ('vbs', 'vbscript', 'visualbasic')

    def __init__(self, window):
        self.window = window
    
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def shift(self, script, s):
        if script.lower().startswith(s):
            return script[len(s):].lstrip()
        return script

    def fix(self, script):
        script = self.shift(script, 'javascript:')
        script = self.shift(script, 'return')
        return script

    # Events handling 
    def handle_onload(self):
        try:
            body = self.window.doc.body
        except:
            body = self.window.doc.getElementsByTagName('body')[0]

        if body and body.tag.has_key('onload'):
            self.window.evalScript(self.fix(body.tag['onload']), tag = 'body')

        if hasattr(self.window, 'onload'):
            self.window.evalScript(self.fix(self.window.onload))

    def handle_onclick(self):
        inputs = self.window._findAll(('input', 'a'))
        for input in inputs:
            for k, v in input.attrs:
                if k in ('onclick', ):
                    self.window.evalScript(self.fix(v))

    def handle_object(self, object):
        log.info(object)

        classid = object.get('classid', None)
        id      = object.get('id', None)

        if classid and id:
            self.window.__dict__[id] = _ActiveXObject(classid, 'id')

    def handle_script(self, script):
        language = script.get('language', 'javascript').lower()
        handler  = getattr(self, "handle_%s" % (language, ), None)
                
        if not handler:
            log.warning("Unhandled script language: %s" % (language, ))
            return

        handler(script)
            
    def handle_javascript(self, script):
        log.info(script)

        if not script.string:
            src = script.get('src', None)
            if not src:
                return

            response, js = self.window._navigator.fetch(src)
            script.string = js

        self.window.evalScript(script.string, tag = script)

    def handle_vbscript(self, script):
        log.info(script)

        if not vbs_parser:
            self.log.warning("VBScript parsing not enabled (vb2py is needed)")
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

    def handle_param(self, param):
        log.info(param)

        name  = param.get('name' , None)
        value = param.get('value', None)

        if 'http' not in value:
            return

        urls = [p for p in value.split() if p.startswith('http')]

        for url in urls:
            response, content = self.window._navigator.fetch(url)
            m = hashlib.md5()
            m.update(content)
            h = m.hexdigest()

            log.info('Saving remote content at %s (MD5: %s)' % (url, h, ))
            with open(h, 'wb') as fd:
                fd.write(content)

    def handle_applet(self, applet):
        log.info(applet)

        archive = applet.get('archive', None)
        if not archive:
            return

        try:
            response, content = self.window._navigator.fetch(archive)
        except:
            return

        log.info('Saving applet %s' % (archive, ))
        _log = logging.getLogger("Thug")
        with open(os.path.join(_log.baseDir, archive.split('/')[-1]), 'wb') as fd:
            fd.write(content)

    def handle_meta(self, meta):
        log.info(meta)

        http_equiv = meta.get('http-equiv', None)
        if not http_equiv or http_equiv != 'refresh':
            return

        content = meta.get('content', None)
        if not content or not 'url' in content:
            return

        timeout = 0
        url     = None

        for s in content.split(';'):
            if s.startswith('url='):
                url = s[4:]
            try:
                timeout = int(s)
            except:
                pass

        if not url:
            return

        response, content = self.window._navigator.fetch(url)
        self.window.doc   = w3c.parseString(content)
        self.window.open(url)
        self.run()

    def handle_frame(self, frame):
        log.info(frame)
        
        if not frame.string:
            src = frame.get('src', None)
            if not src:
                return 

            # FIXME Dirty code should not be allowed :)
            response, content = self.window._navigator.fetch(src)

            doc    = w3c.parseString(content)
            window = Window.Window(src, doc)
            window.open(src)
            
            dft = DFT(window)
            dft.run()

    def handle_iframe(self, iframe):
        self.handle_frame(iframe)

    def handle_body(self, body):
        pass

    def run(self):
        log.info(self.window.doc)

        soup = self.window.doc.doc
        # Dirty hack
        for p in soup.findAll('object'):
            self.handle_object(p)

        for child in soup.recursiveChildGenerator():
            name = getattr(child, "name", None)
            if name is None or name in ('object', ):
                continue

            handler = getattr(self, "handle_%s" % (name, ), None)
            if handler:
                handler(child)

        self.handle_onload()
        self.handle_onclick()
