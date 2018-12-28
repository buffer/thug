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

import logging
log = logging.getLogger("Thug")


class CCInterpreter(object):
    """
        Microsoft Internet Explorer Conditional Comments tiny interpreter
    """
    def __init__(self):
        pass

    def run(self, script):
        script = script.replace('@cc_on!@', '*/!/*')

        if '/*@cc_on' in script:
            script = script.replace('/*@cc_on', '')
            script = script.replace('@_jscript_version', str(log.ThugOpts.Personality.cc_on['_jscript_version']))
            script = script.replace('/*@if', 'if')
            script = script.replace('@if', 'if')
            script = script.replace('@elif', 'else if')
            script = script.replace('@else', 'else')
            script = script.replace('/*@end', '')
            script = script.replace('@end', '')
            script = script.replace('@_alpha', 'false')
            script = script.replace('@_mc680x0', 'false')
            script = script.replace('@_win16', 'false')
            script = script.replace('@_win64', 'false')
            script = script.replace('@_x86', 'true')

            if log.ThugOpts.Personality.platform in ('Win32', ):
                script = script.replace('@_win32', 'true')
                script = script.replace('@_mac', 'false')

            if log.ThugOpts.Personality.platform in ('MacIntel', ):
                script = script.replace('@_win32', 'false')
                script = script.replace('@_mac', 'true')

            script = script.replace('@*/', '')
            script = script.replace('/*@', '')

        return script
