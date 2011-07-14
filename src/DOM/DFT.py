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
import w3c
import hashlib
import logging
import Window
from ActiveX.ActiveX import _ActiveXObject

vbs_parser = True

try:
    #from vb2py.vbparser import convertVBtoPython, VBCodeModule
    import pyjs
except ImportError:
    vbs_parser = False
    pass
    
class DFT(object):
    log        = logging.getLogger("DFT")
    javascript = ('javascript', )
    vbscript   = ('vbs', 'vbscript', 'visualbasic')

    def __init__(self, window, debug = False):
        self.window = window

        if debug:
            self.log.setLevel(logging.DEBUG)
    
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
            if body and body.tag.has_key('onload'):
                self.window.evalScript(self.fix(body.tag['onload']), tag = body.tag.contents[-1])
        except:
            pass

        if hasattr(self.window, 'onload'):
            self.window.evalScript(self.fix(self.window.onload))

    def handle_onclick(self):
        inputs = self.window._findAll('input')
        for input in inputs:
            for k, v in input.attrs:
                if k in ('onclick', ):
                    self.window.evalScript(self.fix(v))

    def handle_object(self, object):
        self.log.debug(object)

        classid = object.get('classid', None)
        id      = object.get('id', None)

        if classid and id:
            self.window.__dict__[id] = _ActiveXObject(classid, 'id')

    def handle_script(self, script):
        self.log.debug(script)

        language = script.get('language', 'javascript').lower()
        handler  = getattr(self, "handle_%s" % (language, ), None)
                
        if not handler:
            self.log.warning("Unhandled script language: %s" % (language, ))
            return

        handler(script)
            
    def handle_javascript(self, script):
        self.log.debug(script)

        if not script.string:
            src = script.get('src', None)
            if not src:
                return

            response, js = self.window._navigator.fetch(src)
            script.setString(js)

        self.window.evalScript(script.string, tag = script)

    def handle_vbscript(self, script):
        self.log.debug(script)

        if not vbs_parser:
            self.log.warning("VBScript parsing not enabled (vb2py is needed)")
            return

        vbs_py = convertVBtoPython(script.string, container = VBCodeModule())
        self.log.warning(vbs_py)

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
        self.log.debug(param)

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

            self.log.warning('Saving remote content at %s (MD5: %s)' % (url, h, ))
            with open(h, 'wb') as fd:
                fd.write(content)

    def handle_applet(self, applet):
        self.log.debug(applet)

        archive = applet.get('archive', None)
        if not archive:
            return

        response, content = self.window._navigator.fetch(archive)
        self.log.warning('Saving applet %s' % (archive, ))
        with open(archive, 'wb') as fd:
            fd.write(content)

    def handle_meta(self, meta):
        self.log.debug(meta)

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
        self.log.warning(frame)
        
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

    def run(self):
        self.log.warning(self.window.doc)

        soup = self.window.doc.doc

        for child in soup.recursiveChildGenerator():
            name = getattr(child, "name", None)
            if name is not None:
                handler = getattr(self, "handle_%s" % (name, ), None)
                if handler: 
                    handler(child)

        self.handle_onload()
        self.handle_onclick()
