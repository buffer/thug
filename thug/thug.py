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

import argparse
import logging
import os
import sys
from .ThugAPI import ThugAPI
from .Plugins.ThugPlugins import ThugPlugins
from .Plugins.ThugPlugins import PRE_ANALYSIS_PLUGINS
from .Plugins.ThugPlugins import POST_ANALYSIS_PLUGINS

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)


class Thug(ThugAPI):
    def __init__(self, args: argparse.Namespace):
        self.args = args
        ThugAPI.__init__(self)

    def list_ua(self):
        msg = """\n    Available User-Agents:\n\n"""

        for key, value in sorted(
            iter(log.ThugOpts.Personality.items()),
            key=lambda k_v: (k_v[1]["id"], k_v[0]),
        ):
            msg += "\t\033[1m{:<22}\033[0m{}\n".format(key, value["description"])  # pylint: disable=consider-using-f-string

        print(msg)
        sys.exit(0)

    def analyze(self):
        p = (
            getattr(self, "run_local")
            if self.args.local or self.args.local_nofetch
            else getattr(self, "run_remote")
        )

        self.set_raise_for_proxy(False)

        for arg_name, arg_value in vars(self.args).items():
            if arg_name in ("url", "local", "local_nofetch"):
                continue

            m = getattr(self, arg_name)
            if m:
                if (
                    arg_name.startswith("add_")
                    and isinstance(arg_value, list)
                    and arg_value
                ):
                    for item in arg_value:
                        m(item)
                elif isinstance(arg_value, str) and arg_value:
                    m(arg_value)
                elif isinstance(arg_value, bool) and arg_value:
                    m()
            else:
                raise RuntimeError(
                    f"Unable to handle the argument {arg_name} with value {arg_value}"
                )

        self.log_init(self.args.url)

        if p:  # pylint:disable=using-constant-test
            ThugPlugins(PRE_ANALYSIS_PLUGINS, self)()
            p(self.args.url)
            ThugPlugins(POST_ANALYSIS_PLUGINS, self)()

        self.log_event()
        return log


def parse_args() -> argparse.Namespace:
    def rules_list(rules_arg: str) -> list[str]:
        return list(map(os.path.abspath, rules_arg.split(",")))

    parser = argparse.ArgumentParser(
        prog="thug",
        description="Thug: Pure Python honeyclient implementation",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Proxy Format:\n\tscheme://[username:password@]host:port (supported schemes: http, socks4, socks5, socks5h)""",
    )

    parser.add_argument("url", help="URL to be analyzed", nargs="?")

    parser.add_argument(
        "-V", "--version", help="Display Thug version", action="store_true"
    )

    parser.add_argument(
        "-i", "--list-ua", help="Display available user agents", action="store_true"
    )

    parser.add_argument(
        "-u",
        "--useragent",
        help="Select a user agent (use option -b for values, default: winxpie60)",
        dest="set_useragent",
    )

    parser.add_argument(
        "-e",
        "--events",
        help="Enable comma-separated specified DOM events handling",
        dest="set_events",
    )

    parser.add_argument(
        "-w",
        "--delay",
        help="Set a maximum setTimeout/setInterval delay value (in milliseconds)",
        dest="set_delay",
    )

    parser.add_argument(
        "-n", "--logdir", help="Set the log output directory", dest="set_log_dir"
    )

    parser.add_argument(
        "-o", "--output", help="Log to a specified file", dest="set_log_output"
    )

    parser.add_argument("-r", "--referer", help="Specify a referer", dest="set_referer")

    parser.add_argument(
        "-p",
        "--proxy",
        help="Specify a proxy (see below for format and supported schemes)",
        dest="set_proxy",
    )

    parser.add_argument(
        "-m",
        "--attachment",
        help="Set the attachment mode",
        dest="set_attachment",
        action="store_true",
    )

    parser.add_argument(
        "-z",
        "--web-tracking",
        help="Enable web client tracking inspection",
        dest="set_web_tracking",
        action="store_true",
    )

    parser.add_argument(
        "-b",
        "--async-prefetch",
        help="Enable async prefetching mode",
        dest="set_async_prefetch",
        action="store_true",
    )

    parser.add_argument(
        "-k",
        "--no-honeyagent",
        help="Disable HoneyAgent support",
        dest="disable_honeyagent",
        action="store_true",
    )

    parser.add_argument(
        "-a",
        "--image-processing",
        help="Enable image processing analysis",
        dest="set_image_processing",
        action="store_true",
    )

    parser.add_argument(
        "-f",
        "--screenshot",
        help="Enable screenshot capturing",
        dest="enable_screenshot",
        action="store_true",
    )

    parser.add_argument(
        "-E",
        "--awis",
        help="Enable AWS Alexa Web Information Service (AWIS)",
        dest="enable_awis",
        action="store_true",
    )

    parser.add_argument(
        "-s",
        "--no-down-prevent",
        help="Disable download prevention mechanism",
        dest="disable_download_prevent",
        action="store_true",
    )

    parser.add_argument(
        "-l", "--local", help="Analyze a locally saved page", action="store_true"
    )

    parser.add_argument(
        "-x",
        "--local-nofetch",
        help="Analyze a locally saved page and prevent remote content fetching",
        action="store_true",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose mode",
        dest="set_verbose",
        action="store_true",
    )

    parser.add_argument(
        "-d", "--debug", help="Enable debug mode", dest="set_debug", action="store_true"
    )

    parser.add_argument(
        "-q",
        "--quiet",
        help="Disable console logging",
        dest="set_log_quiet",
        action="store_true",
    )

    parser.add_argument(
        "-g",
        "--http-debug",
        help="Enable HTTP debug mode",
        dest="set_http_debug",
        action="store_true",
    )

    parser.add_argument(
        "-A",
        "--adobepdf",
        help="Specify Adobe Acrobat Reader version (default: 9.1.0",
        dest="set_acropdf_pdf",
    )

    parser.add_argument(
        "-P",
        "--no-adobepdf",
        help="Disable Adobe Acrobat Reader plugin",
        dest="disable_acropdf",
        action="store_true",
    )

    parser.add_argument(
        "-S",
        "--shockwave",
        help="Specify Shockwave Flash version (default: 10.0.64.0)",
        dest="set_shockwave_flash",
    )

    parser.add_argument(
        "-R",
        "--no-shockwave",
        help="Disable Shockwave Flash plugin",
        dest="disable_shockwave_flash",
        action="store_true",
    )

    parser.add_argument(
        "-J",
        "--javaplugin",
        help="Specify JavaPlugin version (default: 1.6.0.32)",
        dest="set_javaplugin",
    )

    parser.add_argument(
        "-K",
        "--no-javaplugin",
        help="Disable Java plugin",
        dest="disable_javaplugin",
        action="store_true",
    )

    parser.add_argument(
        "-L",
        "--silverlight",
        help="Specify SilverLight version (default: 4.0.50826.0)",
        dest="set_silverlight",
    )

    parser.add_argument(
        "-N",
        "--no-silverlight",
        help="Disable SilverLight plugin",
        dest="disable_silverlight",
        action="store_true",
    )

    parser.add_argument(
        "-t", "--threshold", help="Maximum pages to fetch", dest="set_threshold"
    )

    parser.add_argument(
        "-j",
        "--extensive",
        help="Extensive fetch of linked pages",
        dest="set_extensive",
        action="store_true",
    )

    parser.add_argument(
        "-O",
        "--connect-timeout",
        help="Set the connect timeout (in seconds, default: 10 seconds)",
        dest="set_connect_timeout",
    )

    parser.add_argument(
        "-B",
        "--proxy-connect-timeout",
        help="Set the proxy connect timeout (in seconds, default: 5 seconds)",
        dest="set_proxy_connect_timeout",
    )

    parser.add_argument(
        "-T",
        "--timeout",
        help="Set the analysis timeout (in seconds, default: 600 seconds)",
        dest="set_timeout",
    )

    parser.add_argument(
        "-c",
        "--broken-url",
        help="Set the broken URL mode",
        dest="set_broken_url",
        action="store_true",
    )

    parser.add_argument(
        "--htmlclassifier",
        help="Specify a list of additional (comma separated) HTML classifier rule files",
        type=rules_list,
        dest="add_htmlclassifier",
    )

    parser.add_argument(
        "--urlclassifier",
        help="Specify a list of additional (comma separated) URL classifier rule files",
        type=rules_list,
        dest="add_urlclassifier",
    )

    parser.add_argument(
        "--jsclassifier",
        help="Specify a list of additional (comma separated) JS classifier rule files",
        type=rules_list,
        dest="add_jsclassifier",
    )

    parser.add_argument(
        "--vbsclassifier",
        help="Specify a list of additional (comma separated) VBS classifier rule files",
        type=rules_list,
        dest="add_vbsclassifier",
    )

    parser.add_argument(
        "--sampleclassifier",
        help="Specify a list of additional (comma separated) Sample classifier rule files",
        type=rules_list,
        dest="add_sampleclassifier",
    )

    parser.add_argument(
        "--textclassifier",
        help="Specify a list of additional (comma separated) Text classifier rule files",
        type=rules_list,
        dest="add_textclassifier",
    )

    parser.add_argument(
        "--cookieclassifier",
        help="Specify a list of additional (comma separated) Cookie classifier rule files",
        type=rules_list,
        dest="add_cookieclassifier",
    )

    parser.add_argument(
        "--imageclassifier",
        help="Specify a list of additional (comma separated) Image classifier rule files",
        type=rules_list,
        dest="add_imageclassifier",
    )

    parser.add_argument(
        "--htmlfilter",
        help="Specify a list of additional (comma separated) HTML filter files",
        type=rules_list,
        dest="add_htmlfilter",
    )

    parser.add_argument(
        "--urlfilter",
        help="Specify a list of additional (comma separated) URL filter files",
        type=rules_list,
        dest="add_urlfilter",
    )

    parser.add_argument(
        "--jsfilter",
        help="Specify a list of additional (comma separated) JS filter files",
        type=rules_list,
        dest="add_jsfilter",
    )

    parser.add_argument(
        "--vbsfilter",
        help="Specify a list of additional (comma separated) VBS filter files",
        type=rules_list,
        dest="add_vbsfilter",
    )

    parser.add_argument(
        "--samplefilter",
        help="Specify a list of additional (comma separated) Sample filter files",
        type=rules_list,
        dest="add_samplefilter",
    )

    parser.add_argument(
        "--textfilter",
        help="Specify a list of additional (comma separated) Text filter files",
        type=rules_list,
        dest="add_textfilter",
    )

    parser.add_argument(
        "--cookiefilter",
        help="Specify a list of additional (comma separated) Cookie filter files",
        type=rules_list,
        dest="add_cookiefilter",
    )

    parser.add_argument(
        "--imagefilter",
        help="Specify a list of additional (comma separated) Image filter files",
        type=rules_list,
        dest="add_imagefilter",
    )

    parser.add_argument(
        "-F",
        "--file-logging",
        help="Enable file logging mode (default: disabled)",
        dest="set_file_logging",
        action="store_true",
    )

    parser.add_argument(
        "-Z",
        "--json-logging",
        help="Enable JSON logging mode (default: disabled)",
        dest="set_json_logging",
        action="store_true",
    )

    parser.add_argument(
        "-W",
        "--features-logging",
        help="Enable features logging mode (default: disabled)",
        dest="set_features_logging",
        action="store_true",
    )

    parser.add_argument(
        "-G",
        "--elasticsearch-logging",
        help="Enable ElasticSearch logging mode (default: disabled)",
        dest="set_elasticsearch_logging",
        action="store_true",
    )

    parser.add_argument(
        "-D",
        "--mongodb-address",
        help="Specify address and port of the MongoDB instance (format: host:port)",
        dest="set_mongodb_address",
    )

    parser.add_argument(
        "-Y",
        "--no-code-logging",
        help="Disable code logging",
        dest="disable_code_logging",
        action="store_true",
    )

    parser.add_argument(
        "-U",
        "--no-cert-logging",
        help="Disable SSL/TLS certificate logging",
        dest="disable_cert_logging",
        action="store_true",
    )

    args = parser.parse_args()

    if not any([args.url, args.local, args.local_nofetch, args.version, args.list_ua]):
        parser.print_help()
        parser.exit()

    return args


def main():
    args = parse_args()

    if not os.getenv("THUG_PROFILE", None):
        Thug(args)()
    else:
        import io
        import cProfile
        import pstats
        import tempfile

        profiler = cProfile.Profile()
        profiler.enable()
        Thug(args)()
        profiler.disable()

        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats("cumulative")
        ps.print_stats()

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="thug-profiler-",
            suffix=".log",
            delete=False,
        ) as fd:
            print(f"Saving profiler results to {fd.name}")
            fd.write(s.getvalue())


if __name__ == "__main__":
    main()
