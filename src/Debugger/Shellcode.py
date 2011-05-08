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

import PyV8
import struct
import pylibemu
from Debugger import Debugger

class Shellcode:
    def __init__(self, ctxt, ast, script):
        self.script = script
        self.ctxt   = ctxt
        self.ast    = ast
        self.emu    = pylibemu.Emulator()

    def run(self):
        with Debugger() as dbg:
            emu = pylibemu.Emulator()
            vars = self.ctxt.locals
            self.ctxt.eval(self.script)

            #print self.ast.names
            #print vars.keys()

            for name in self.ast.names:
                s    = None
                skip = False

                if name in vars.keys():
                    s = vars[name]
                if not s:
                    continue
              
                print "[*] Testing variable: %s" % (name, )
                emu.new()
                #print s
                try:
                    shellcode = s.decode('utf-8')
                except:
                    shellcode = s

                sc = b''
                try:
                    for c in shellcode:
                        sc += struct.pack('<H', ord(c))
                except:
                    continue
                    
                offset = emu.shellcode_getpc_test(sc)
                if offset < 0:
                     offset = 0
                
                emu.prepare(sc, offset)
                emu.test()
                emu.free()

