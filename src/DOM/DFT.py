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

from ActiveX.ActiveX import _ActiveXObject

class DFT(object):
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
            if body and body.tag.has_key('onload'):
                self.window.evalScript(self.fix(body.tag['onload']), tag = body.tag.contents[-1])
        except:
            pass

        if hasattr(self.window, 'onload'):
            self.window.evalScript(self.fix(self.window.onload))

    def handle_onclick(self, f):
        inputs = self.window._findAll('input')
        for input in inputs:
            for k, v in input.attrs:
                if k in ('onclick', ):
                    self.window.evalScript(self.fix(v))

    def handle_object(self, object):
        print object
        classid = object.get('classid', None)
        id      = object.get('id', None)

        if classid and id:
            self.window.__dict__[id] = _ActiveXObject(classid, 'id')

    def handle_script(self, script):
        if not script.string:
            src = script.get('src', None)
            if not src:
                return

            response, js = self.window._navigator.fetch(src)
            script.setString(js)

        self.window.evalScript(script.string, tag = script)

    def handle_onclick(self):
        inputs = self.window._findAll('input')
        for input in inputs:
            for k, v in input.attrs:
                if k in ('onclick', ):
                    self.window.evalScript(self.fix(v))

    def run(self):
        soup = self.window.doc.doc

        for child in soup.recursiveChildGenerator():
            name = getattr(child, "name", None)
            if name is not None:
                handler = getattr(self, "handle_%s" % (name, ), None)
                if handler: 
                    handler(child)

        self.handle_onload()
        self.handle_onclick()
