#!/usr/bin/env python
#
# CCInterpreter.py
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

import traceback
import logging
log = logging.getLogger("Thug")

class CCInterpreter(object):
    """
        Microsoft Internet Explorer Conditional Comments tiny interpreter
    """
    def __init__(self):
        pass

    def run(self, script):
        try:
            enc     = log.Encoding.detect(script)
            _script = script.decode(enc['encoding'])
            _script = _script.replace('@cc_on!@', '*/!/*')
        except:
            traceback.print_exc()
            return script

        if '/*@cc_on' in _script:
            _script = _script.replace('/*@cc_on', '')
            _script = _script.replace('@_jscript_version', log.ThugOpts.Personality.cc_on['_jscript_version'].decode(enc['encoding']))
            _script = _script.replace('/*@if', 'if')
            _script = _script.replace('@if', 'if')
            _script = _script.replace('@elif', 'else if')
            _script = _script.replace('@else', 'else')
            _script = _script.replace('/*@end', '')
            _script = _script.replace('@end', '')
            _script = _script.replace('@_win64', 'false')
            _script = _script.replace('@_win32', 'true')
            _script = _script.replace('@_win16', 'false')
            _script = _script.replace('@*/', '')
            _script = _script.replace('/*@', '')

        return _script
