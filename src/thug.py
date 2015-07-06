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
import logging

from ThugAPI import *
from Plugins.ThugPlugins import *

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)


class Thug(ThugAPI):
    def __init__(self, args):
        ThugAPI.__init__(self, args)

    def usage(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        python thug.py [ options ] url

    Options:
        -h, --help          \tDisplay this help information
        -V, --version       \tDisplay Thug version
        -u, --useragent=    \tSelect a user agent (see below for values, default: winxpie60)
        -e, --events=       \tEnable comma-separated specified DOM events handling
        -w, --delay=        \tSet a maximum setTimeout/setInterval delay value (in milliseconds)
        -n, --logdir=       \tSet the log output directory
        -o, --output=       \tLog to a specified file
        -r, --referer=      \tSpecify a referer
        -p, --proxy=        \tSpecify a proxy (see below for format and supported schemes)
        -l, --local         \tAnalyze a locally saved page
        -x, --local-nofetch \tAnalyze a locally saved page and prevent remote content fetching
        -v, --verbose       \tEnable verbose mode
        -d, --debug         \tEnable debug mode
        -q, --quiet         \tDisable console logging
        -m, --no-cache      \tDisable local web cache
        -a, --ast-debug     \tEnable AST debug mode (requires debug mode)
        -g, --http-debug    \tEnable HTTP debug mode 
        -t, --threshold     \tMaximum pages to fetch
        -E, --extensive     \tExtensive fetch of linked pages
        -T, --timeout=      \tSet the analysis timeout (in seconds)
        -B, --broken-url    \tSet the broken URL mode
        -y, --vtquery       \tQuery VirusTotal for samples analysis
        -s, --vtsubmit      \tSubmit samples to VirusTotal
        -z, --web-tracking  \tEnable web client tracking inspection
        -N, --no-honeyagent \tDisable HoneyAgent support

        Plugins:
        -A, --adobepdf=     \tSpecify the Adobe Acrobat Reader version (default: 9.1.0)
        -P, --no-adobepdf   \tDisable Adobe Acrobat Reader plugin
        -S, --shockwave=    \tSpecify the Shockwave Flash version (default: 10.0.64.0)
        -R, --no-shockwave  \tDisable Shockwave Flash plugin
        -J, --javaplugin=   \tSpecify the JavaPlugin version (default: 1.6.0.32)
        -K, --no-javaplugin \tDisable Java plugin

        Classifiers:
        -Q, --urlclassifier \tSpecify a list of additional (comma separated) URL classifier rule files
        -W, --jsclassifier  \tSpecify a list of additional (comma separated) JS classifier rule files
        -C, --sampleclassifier \tSpecify a list of additional (comma separated) sample classifier rule files

        Logging:
        -F, --file-logging  \tEnable file logging mode (default: disabled)
        -Z, --json-logging  \tEnable JSON logging mode (default: disabled)
        -M, --maec11-logging\tEnable MAEC11 logging mode (default: disabled)
        -D, --mongodb-address\tSpecify address and port of the MongoDB instance ("host:port")

    Proxy Format:
        scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)

    Available User-Agents:
"""
        for key, value in sorted(iter(log.ThugOpts.Personality.items()), key = lambda k_v: (k_v[1]['id'], k_v[0])):
            msg += "\t%s\t\t%s\n" % (key, value['description'], )

        print(msg)
        sys.exit(0)

    def analyze(self):
        p = getattr(self, 'run_remote', None)

        try:
            options, args = getopt.getopt(self.args,
                                          'hVu:e:w:n:o:r:p:yszNlxvdqmagA:PS:RJ:Kt:ET:BQ:W:C:FZMD:',
                ['help',
                'version',
                'useragent=',
                'events=',
                'delay=',
                'logdir=',
                'output=',
                'referer=',
                'proxy=',
                'vtquery',
                'vtsubmit',
                'web-tracking',
                'no-honeyagent',
                'local',
                'local-nofetch',
                'verbose',
                'debug',
                'quiet',
                'no-cache',
                'ast-debug',
                'http-debug',
                'adobepdf=',
                'no-adobepdf',
                'shockwave=',
                'no-shockwave',
                'javaplugin=',
                'no-javaplugin',
                'threshold=',
                'extensive',
                'timeout=',
                'broken-url',
                'urlclassifier=',
                'jsclassifier=',
                'sampleclassifier=',
                'file-logging',
                'json-logging',
                'maec11-logging',
                'mongodb-address=',
                ])
        except getopt.GetoptError:
            self.usage()

        if not options and not args:
            self.usage()

        for option in options:
            if option[0] in ('-h', '--help'):
                self.usage()
            elif option[0] in ('-V', '--version'):
                self.version()

        for option in options:
            if option[0] in ('-u', '--useragent', ):
                self.set_useragent(option[1])
            elif option[0] in ('-e', '--events'):
                self.set_events(option[1])
            elif option[0] in ('-w', '--delay'):
                self.set_delay(option[1])
            elif option[0] in ('-r', '--referer', ):
                self.set_referer(option[1])
            elif option[0] in ('-p', '--proxy', ):
                self.set_proxy(option[1])
            elif option[0] in ('-y', '--vtquery', ):
                self.set_vt_query()
            elif option[0] in ('-s', '--vtsubmit', ):
                self.set_vt_submit()
            elif option[0] in ('-z', '--web-tracking', ):
                self.set_web_tracking()
            elif option[0] in ('-N', '--no-honeyagent', ):
                self.disable_honeyagent()
            elif option[0] in ('-l', '--local', ):
                p = getattr(self, 'run_local')
            elif option[0] in ('-x', '--local-nofetch', ):
                p = getattr(self, 'run_local')
                self.set_no_fetch()
            elif option[0] in ('-v', '--verbose', ):
                self.set_verbose()
            elif option[0] in ('-d', '--debug', ):
                self.set_debug()
            elif option[0] in ('-m', '--no-cache'):
                self.set_no_cache()
            elif option[0] in ('-a', '--ast-debug', ):
                self.set_ast_debug()
            elif option[0] in ('-g', '--http-debug', ):
                self.set_http_debug()
            elif option[0] in ('-A', '--adobepdf', ):
                self.set_acropdf_pdf(option[1])
            elif option[0] in ('-P', '--no-adobepdf', ):
                self.disable_acropdf()
            elif option[0] in ('-S', '--shockwave', ):
                self.set_shockwave_flash(option[1])
            elif option[0] in ('-R', '--no-shockwave', ):
                self.disable_shockwave_flash()
            elif option[0] in ('-J', '--javaplugin', ):
                self.set_javaplugin(option[1])
            elif option[0] in ('-K', '--no-javaplugin', ):
                self.disable_javaplugin()
            elif option[0] in ('-t', '--threshold', ):
                self.set_threshold(option[1])
            elif option[0] in ('-E', '--extensive', ):
                self.set_extensive()
            elif option[0] in ('-T', '--timeout', ):
                self.set_timeout(option[1])
            elif option[0] in ('-Q', '--urlclassifier'):
                for classifier in option[1].split(','):
                    self.add_urlclassifier(os.path.abspath(classifier))
            elif option[0] in ('-W', '--jsclassifier'):
                for classifier in option[1].split(','):
                    self.add_jsclassifier(os.path.abspath(classifier))
            elif option[0] in ('-C', '--sampleclassifier'):
                    for classifier in option[1].split(','):
                        self.add_sampleclassifier(os.path.abspath(classifier))
            elif option[0] in ('-B', '--broken-url', ):
                self.set_broken_url()
            elif option[0] in ('-F', '--file-logging', ):
                self.set_file_logging()
            elif option[0] in ('-Z', '--json-logging', ):
                self.set_json_logging()
            elif option[0] in ('-M', '--maec11-logging', ):
                self.set_maec11_logging()
            elif option[0] in ('-D', '--mongodb-address', ):
                self.set_mongodb_address(option[1])

        self.log_init(args[0])

        for option in options:
            if option[0] in ('-n', '--logdir'):
                self.set_log_dir(option[1])
            elif option[0] in ('-o', '--output', ):
                self.set_log_output(option[1])
            elif option[0] in ('-q', '--quiet', ):
                self.set_log_quiet()

        if p:
            ThugPlugins(PRE_ANALYSIS_PLUGINS, self)()
            p(args[0])
            ThugPlugins(POST_ANALYSIS_PLUGINS, self)()

        self.log_event()
        return log


if __name__ == "__main__":
    if not os.getenv('THUG_PROFILE', None):
        Thug(sys.argv[1:])()
    else:
        import cProfile
        import pstats
        cProfile.run('Thug(sys.argv[1:])()', 'countprof')
        p = pstats.Stats('countprof')
        p.print_stats()
