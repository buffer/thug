#!/usr/bin/env python
#
# thug.py
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

import sys
import getopt
from DOM import w3c, Window, DFT


class Thug:
    def __init__(self, args):
        self.args      = args
        self.debug     = False
        self.verbose   = False
        self.output    = None
        self.useragent = None

    def __call__(self):
        self.analyze()

    def usage(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        python thug.py [ options ] url

    Options:
        -h, --help          Display this help information
        -u, --useragent=    
        -o, --output=       Log to a specified file
        -l, --local         
        -v, --verbose       Enable verbose mode    
        -d, --debug         Enable debug mode
"""
        print msg
        sys.exit(0)

    def run_local(self, url):
        html   = open(url, 'r').read()
        doc    = w3c.parseString(html)
        window = Window.Window('about:blank', doc)
        window.open()
    
        dft = DFT.DFT(window)
        dft.run()

    def analyze(self):
        p = getattr(self, 'run_remote', None)

        try:
            options, args = getopt.getopt(self.args, 'hu:o:lvd',
                ['help', 
                'useragent=', 
                'logfile=', 
                'verbose',
                'debug', 
                ])
        except getopt.GetoptError, exp:
            self.usage()

        if not options and not args:
            self.usage()

        for option in options:
            if option[0] == '-h' or option[0] == '--help':
                self.usage()
            if option[0] == '-u' or option[0] == '--useragent':
                self.useragent = option[1]
            if option[0] == '-o' or option[0] == '--output':
                self.output = option[1]
            if option[0] == '-l' or option[0] == '--local':
                p = getattr(self, 'run_local')
            if option[0] == '-v' or option[0] == '--verbose':
                self.verbose = True
            if option[0] == '-d' or option[0] == '--debug':
                self.debug = True

        if p:
            p(args[0])

if __name__ == "__main__":
    Thug(sys.argv[1:])()
