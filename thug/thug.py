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

import os
import sys
import getopt
import logging

from .ThugAPI import ThugAPI
from .Plugins.ThugPlugins import ThugPlugins
from .Plugins.ThugPlugins import PRE_ANALYSIS_PLUGINS
from .Plugins.ThugPlugins import POST_ANALYSIS_PLUGINS

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)


class Thug(ThugAPI):
    def __init__(self, args):
        self.args = args
        ThugAPI.__init__(self)

    def usage(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        thug [ options ] url

    Options:
        -h, --help              \tDisplay this help information
        -V, --version           \tDisplay Thug version
        -i, --list-ua           \tDisplay available user agents
        -u, --useragent=        \tSelect a user agent (use option -b for values, default: winxpie60)
        -e, --events=           \tEnable comma-separated specified DOM events handling
        -w, --delay=            \tSet a maximum setTimeout/setInterval delay value (in milliseconds)
        -n, --logdir=           \tSet the log output directory
        -o, --output=           \tLog to a specified file
        -r, --referer           \tSpecify a referer
        -p, --proxy=            \tSpecify a proxy (see below for format and supported schemes)
        -m, --attachment        \tSet the attachment mode
        -l, --local             \tAnalyze a locally saved page
        -x, --local-nofetch     \tAnalyze a locally saved page and prevent remote content fetching
        -v, --verbose           \tEnable verbose mode
        -d, --debug             \tEnable debug mode
        -q, --quiet             \tDisable console logging
        -a, --ast-debug         \tEnable AST debug mode (requires debug mode)
        -g, --http-debug        \tEnable HTTP debug mode
        -t, --threshold         \tMaximum pages to fetch
        -j, --extensive         \tExtensive fetch of linked pages
        -O, --connect-timeout   \tSet the connect timeout (in seconds, default: 10 seconds)
        -T, --timeout=          \tSet the analysis timeout (in seconds, default: 600 seconds)
        -c, --broken-url        \tSet the broken URL mode
        -y, --vtquery           \tQuery VirusTotal for samples analysis
        -s, --vtsubmit          \tSubmit samples to VirusTotal
        -b, --vt-apikey=        \tVirusTotal API key to be used at runtime
        -z, --web-tracking      \tEnable web client tracking inspection
        -k, --no-honeyagent     \tDisable HoneyAgent support

        Plugins:
        -A, --adobepdf=         \tSpecify Adobe Acrobat Reader version (default: 9.1.0)
        -P, --no-adobepdf       \tDisable Adobe Acrobat Reader plugin
        -S, --shockwave=        \tSpecify Shockwave Flash version (default: 10.0.64.0)
        -R, --no-shockwave      \tDisable Shockwave Flash plugin
        -J, --javaplugin=       \tSpecify JavaPlugin version (default: 1.6.0.32)
        -K, --no-javaplugin     \tDisable Java plugin
        -L, --silverlight       \tSpecify SilverLight version (default: 4.0.50826.0)
        -N, --no-silverlight    \tDisable SilverLight plugin

        Classifiers:
        --htmlclassifier=       \tSpecify a list of additional (comma separated) HTML classifier rule files
        --urlclassifier=        \tSpecify a list of additional (comma separated) URL classifier rule files
        --jsclassifier=         \tSpecify a list of additional (comma separated) JS classifier rule files
        --vbsclassifier=        \tSpecify a list of additional (comma separated) VBS classifier rule files
        --sampleclassifier=     \tSpecify a list of additional (comma separated) Sample classifier rule files
        --textclassifier=       \tSpecify a list of additional (comma separated) Text classifier rule files
        --htmlfilter=           \tSpecify a list of additional (comma separated) HTML filter files
        --urlfilter=            \tSpecify a list of additional (comma separated) URL filter files
        --jsfilter=             \tSpecify a list of additional (comma separated) JS filter files
        --vbsfilter=            \tSpecify a list of additional (comma separated) VBS filter files
        --samplefilter=         \tSpecify a list of additional (comma separated) Sample filter files
        --textfilter=           \tSpecify a list of additional (comma separated) Text filter files

        Logging:
        -F, --file-logging      \tEnable file logging mode (default: disabled)
        -Z, --json-logging      \tEnable JSON logging mode (default: disabled)
        -M, --maec11-logging    \tEnable MAEC11 logging mode (default: disabled)
        -G, --elasticsearch-logging\tEnable ElasticSearch logging mode (default: disabled)
        -D, --mongodb-address=  \tSpecify address and port of the MongoDB instance (format: host:port)
        -Y, --no-code-logging   \tDisable code logging
        -U, --no-cert-logging   \tDisable SSL/TLS certificate logging

    Proxy Format:
        scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)
"""

        print(msg)
        sys.exit(0)

    def list_ua(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Available User-Agents:
"""

        for key, value in sorted(iter(log.ThugOpts.Personality.items()), key = lambda k_v: (k_v[1]['id'], k_v[0])):
            msg += "\t\033[1m{:<22}\033[0m{}\n".format(key, value['description'])

        print(msg)
        sys.exit(0)

    def analyze(self):
        p = getattr(self, 'run_remote', None)

        try:
            options, args = getopt.getopt(self.args,
                                          'hViu:e:w:n:o:r:p:myszklxvdqagA:PS:RJ:KL:Nt:jO:T:cFZMGYUD:b:',
                ['help',
                'version',
                'list-ua',
                'useragent=',
                'events=',
                'delay=',
                'logdir=',
                'output=',
                'referer=',
                'proxy=',
                'attachment',
                'vtquery',
                'vtsubmit',
                'web-tracking',
                'no-honeyagent',
                'local',
                'local-nofetch',
                'verbose',
                'debug',
                'quiet',
                'ast-debug',
                'http-debug',
                'adobepdf=',
                'no-adobepdf',
                'shockwave=',
                'no-shockwave',
                'javaplugin=',
                'no-javaplugin',
                'silverlight=',
                'no-silverlight',
                'threshold=',
                'extensive',
                'connect-timeout=',
                'timeout=',
                'broken-url',
                'htmlclassifier=',
                'urlclassifier=',
                'jsclassifier=',
                'vbsclassifier=',
                'sampleclassifier=',
                'textclassifier=',
                'htmlfilter=',
                'urlfilter=',
                'jsfilter=',
                'vbsfilter=',
                'samplefilter=',
                'textfilter='
                'file-logging',
                'json-logging',
                'maec11-logging',
                'elasticsearch-logging',
                'no-code-logging',
                'no-cert-logging',
                'mongodb-address=',
                'vt-apikey=',
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
            elif option[0] in ('-i', '--list-ua'):
                self.list_ua()

        self.set_raise_for_proxy(False)  # FIXME: A better way to handle this?

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
            elif option[0] in ('-m', '--attachment', ):
                self.set_attachment()
            elif option[0] in ('-y', '--vtquery', ):
                self.set_vt_query()
            elif option[0] in ('-s', '--vtsubmit', ):
                self.set_vt_submit()
            elif option[0] in ('-b', '--vt-apikey', ):
                self.set_vt_runtime_apikey(option[1])
            elif option[0] in ('-z', '--web-tracking', ):
                self.set_web_tracking()
            elif option[0] in ('-k', '--no-honeyagent', ):
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
            elif option[0] in ('-L', '--silverlight', ):
                self.set_silverlight(option[1])
            elif option[0] in ('-N', '--no-silverlight', ):
                self.disable_silverlight()
            elif option[0] in ('-t', '--threshold', ):
                self.set_threshold(option[1])
            elif option[0] in ('-j', '--extensive', ):
                self.set_extensive()
            elif option[0] in ('-O', '--connect-timeout', ):
                self.set_connect_timeout(option[1])
            elif option[0] in ('-T', '--timeout', ):
                self.set_timeout(option[1])
            elif option[0] in ('--htmlclassifier', ):
                for classifier in option[1].split(','):
                    self.add_htmlclassifier(os.path.abspath(classifier))
            elif option[0] in ('--urlclassifier', ):
                for classifier in option[1].split(','):
                    self.add_urlclassifier(os.path.abspath(classifier))
            elif option[0] in ('--jsclassifier', ):
                for classifier in option[1].split(','):
                    self.add_jsclassifier(os.path.abspath(classifier))
            elif option[0] in ('--vbsclassifier', ):
                for classifier in option[1].split(','):
                    self.add_vbsclassifier(os.path.abspath(classifier))
            elif option[0] in ('--sampleclassifier', ):
                for classifier in option[1].split(','):
                    self.add_sampleclassifier(os.path.abspath(classifier))
            elif option[0] in ('--textclassifier', ):
                for classifier in option[1].split(','):
                    self.add_textclassifier(os.path.abspath(classifier))
            elif option[0] in ('--htmlfilter', ):
                for f in option[1].split(','):
                    self.add_htmlfilter(os.path.abspath(f))
            elif option[0] in ('--urlfilter', ):
                for f in option[1].split(','):
                    self.add_urlfilter(os.path.abspath(f))
            elif option[0] in ('--jsfilter', ):
                for f in option[1].split(','):
                    self.add_jsfilter(os.path.abspath(f))
            elif option[0] in ('--vbsfilter', ):
                for f in option[1].split(','):
                    self.add_vbsfilter(os.path.abspath(f))
            elif option[0] in ('--samplefilter', ):
                for f in option[1].split(','):
                    self.add_samplefilter(os.path.abspath(f))
            elif option[0] in ('--textfilter', ):
                for f in option[1].split(','):
                    self.add_textfilter(os.path.abspath(f))
            elif option[0] in ('-c', '--broken-url', ):
                self.set_broken_url()
            elif option[0] in ('-F', '--file-logging', ):
                self.set_file_logging()
            elif option[0] in ('-Z', '--json-logging', ):
                self.set_json_logging()
            elif option[0] in ('-M', '--maec11-logging', ):
                self.set_maec11_logging()
            elif option[0] in ('-G', '--elasticsearch-logging', ):
                self.set_elasticsearch_logging()
            elif option[0] in ('-Y', '--no-code-logging', ):
                self.disable_code_logging()
            elif option[0] in ('-U', '--no-cert-logging', ):
                self.disable_cert_logging()
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


def main():
    if not os.getenv('THUG_PROFILE', None):
        Thug(sys.argv[1:])()
    else:
        from six import StringIO
        import cProfile
        import pstats

        profiler = cProfile.Profile()
        profiler.enable()
        Thug(sys.argv[1:])()
        profiler.disable()

        s  = StringIO()
        ps = pstats.Stats(profiler, stream = s).sort_stats('cumulative')
        ps.print_stats()
        with open('/tmp/thug-profiler.log', 'w') as fd:
            fd.write(s.getvalue())


if __name__ == "__main__":
    main()
