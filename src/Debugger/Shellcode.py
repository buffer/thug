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

class Shellcode(object):
    emu = pylibemu.Emulator(enable_hooks = False)

    def __init__(self, window, ctxt, ast, script):
        self.window  = window
        self.script  = script
        self.ctxt    = ctxt
        self.ast     = ast
        self.offsets = set()

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
                self.window._navigator.fetch(p[1], redirect_type = "Found URLDownloadToFile")
                log.ThugLogging.shellcode_urls.add(url)
            except:
                pass

            profile = profile[1:]

    def search_url(self, sc):
        offset = sc.find('http')
        
        if offset > 0:
            url = sc[offset:].split()[0]
            if url in log.ThugLogging.shellcode_urls:
                return

            log.info('[Shellcode Analysis] URL Detected: %s' % (url, ))

            try:
                self.window._navigator.fetch(url, redirect_type = "URL found")
                log.ThugLogging.shellcode_urls.add(url)
            except:
                pass

    def run(self):
        trace = None

        with Debugger() as dbg:
            dbg._context = self.ctxt
            vars = self.ctxt.locals
            #dbg.debugBreak()

            try:
                result = self.ctxt.eval(self.script)
            except UnicodeDecodeError:
                enc = chardet.detect(self.script)
                try:
                    result = self.ctxt.eval(self.script.decode(enc['encoding']))
                except:
                    trace = traceback.format_exc()
            except:
                trace = traceback.format_exc()
            finally:
                #PyV8.JSEngine.collect()
                if trace:
                    log.ThugLogging.log_warning(trace)
                    return None

            for name in self.ast.names:
                s = None

                if not hasattr(vars, "keys"):
                    continue

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
                    log.warning("[Shellcode Profile]\n\n%s" % (emu.emu_profile_output, ))
                    self.check_URLDownloadToFile(emu)

                self.emu.free()
                self.search_url(s)
            
        return result
