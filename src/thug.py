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
import os
import getopt
import datetime
import urlparse
import hashlib
import logging

from DOM.W3C import w3c
from DOM.Personality import Personality
from DOM import Window, DFT

log = logging.getLogger('Thug')
log.setLevel(logging.WARN)

class Thug:
    def __init__(self, args):
        self.args      = args
        self.useragent = 'xpie61'

    def __call__(self):
        self.analyze()

    def usage(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        python thug.py [ options ] url

    Options:
        -h, --help          \tDisplay this help information
        -u, --useragent=    
        -o, --output=       \tLog to a specified file
        -l, --local         
        -v, --verbose       \tEnable verbose mode    
        -d, --debug         \tEnable debug mode

    Available User-Agents:
"""
        for key, value in sorted(Personality.iteritems(), key = lambda (k, v): (v['id'], k)):
            msg += "\t%s\t\t\t%s\n" % (key, value['description'], )

        print msg
        sys.exit(0)

    def run(self, window):
        dft = DFT.DFT(window)
        dft.run()

    def run_local(self, url):
        html   = open(url, 'r').read()
        doc    = w3c.parseString(html)
        window = Window.Window('about:blank', doc, personality = self.useragent)
        window.open()
        self.run(window)

    def run_remote(self, url):
        doc    = w3c.parseString('')
        window = Window.Window('about:blank', doc, personality = self.useragent)
        window = window.open(url)
        self.run(window)

    def build_logbasedir(self, url):
        t = datetime.datetime.now()
        m = hashlib.md5()
        m.update(url)

        base = os.getenv('THUG_LOGBASE', '..')
        log.baseDir = os.path.join(base, 'logs', m.hexdigest(), t.strftime("%Y%m%d%H%M%S"))
        os.makedirs(log.baseDir)

        with open(os.path.join(base, 'logs', 'thug.csv'), 'a') as fd:
            fd.write('%s,%s\n' % (m.hexdigest(), url, ))

    def analyze(self):
        t = datetime.datetime.now()
        p = getattr(self, 'run_remote', None)

        try:
            options, args = getopt.getopt(self.args, 'hu:o:lvd',
                ['help', 
                'useragent=', 
                'logfile=', 
                'verbose',
                'debug', 
                ])
        except getopt.GetoptError:
            self.usage()

        if not options and not args:
            self.usage()

        for option in options:
            if option[0] == '-h' or option[0] == '--help':
                self.usage()

        self.build_logbasedir(args[0])

        for option in options:
            if option[0] == '-u' or option[0] == '--useragent':
                self.useragent = option[1]
            if option[0] == '-o' or option[0] == '--output':
                fh = logging.FileHandler(os.path.join(log.baseDir, option[1]))
                log.addHandler(fh)
            if option[0] == '-l' or option[0] == '--local':
                p = getattr(self, 'run_local')
            if option[0] == '-v' or option[0] == '--verbose':
                log.setLevel(logging.INFO)
            if option[0] == '-d' or option[0] == '--debug':
                log.setLevel(logging.DEBUG)

        if p:
            log.info(args[0])
            p(args[0])

if __name__ == "__main__":
    Thug(sys.argv[1:])()
