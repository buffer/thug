#!/usr/bin/env python
#
# Shellcode.py
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
import PyV8 
import string
import struct
import hashlib
import logging
import traceback
import chardet
import pylibemu
from .Debugger import Debugger
from DOM.W3C.Node import Node

log = logging.getLogger("Thug")

class Shellcode:
    emu = pylibemu.Emulator()

    def __init__(self, window, ctxt, ast, script):
	self.window  = window
        self.script  = script
        self.ctxt    = ctxt
        self.ast     = ast
        self.offsets = set()

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
            
    def search_url(self, sc):
        offset = sc.find('http')
        
        if offset > 0:
            url = sc[offset:].split()[0]
            log.info('[Shellcode Analysis] URL Detected: %s' % (url, ))
            self._fetch(url)

    def run(self):
        result = None

        with Debugger() as dbg:
            dbg._context = self.ctxt
            vars = self.ctxt.locals
            #dbg.debugBreak()

            try:
                result = self.ctxt.eval(self.script)
            except UnicodeDecodeError:
                enc    = chardet.detect(self.script)
                result = self.ctxt.eval(self.script.decode(enc['encoding']))
            except:
                log.debug(traceback.format_exc())
                return result

            for name in self.ast.names:
                s = None

                if name in vars.keys():
                    s = vars[name]

                if not s:
                    continue

                if not isinstance(s, basestring):
                    continue
              
                log.debug("[Shellcode] Testing variable: %s" % (name, ))
                self.emu.run(s)

                if self.emu.emu_profile_output:
                    log.ThugLogging.add_code_snippet(self.emu.emu_profile_output, 'Assembly', 'Shellcode')
                    log.warning(self.emu.emu_profile_output)
                    libemu = True

                self.emu.free()
                #self.search_url(s)
            
        return result
