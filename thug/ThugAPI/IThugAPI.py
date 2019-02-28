#!/usr/bin/env python
#
# IThugAPI.py
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

import zope.interface


class IThugAPI(zope.interface.Interface):
    def version():
        """
        Print Thug version and exit

        @return: None
        """

    def get_useragent():
        """
        get_useragent

        Return the emulated user agent

        @return: user agent string
        """

    def set_useragent(useragent):
        """
        set_useragent

        Set the user agent to emulate

        @param useragent: the user agent to emulate
        @type useragent: C{str}
        @return: None
        """

    def get_events():
        """
        get_events

        Return the DOM events to emulate
        Note: the load and mousemove are emulated by default and are not included in
        the returned list

        @return: List of the DOM events to emulate
        """

    def set_events(events):
        """
        set_events

        Set the DOM events to emulate
        Note: the load and mousemove events are emulated by default and do not
        need to be added through set_events

        @param events: comma separated list of DOM events to emulate
        @type events: C{str}
        @return: None
        """

    def get_delay():
        """
        get_delay

        Return the maximum setTimeout/setInterval delay value (in milliseconds)

        @return: maximum delay value (in milliseconds)
        """

    def set_delay(delay):
        """
        set_delay

        Set a maximum setTimeout/setInterval delay value (in milliseconds)

        @param delay: maximum delay value (in milliseconds)
        @type delay: C{int}
        @return: None
        """

    def get_attachment():
        """
        get_attachment

        Return True if the attachment mode is set, False otherwise

        @return: boolean
        """

    def set_attachment(attachment):
        """
        set_attachment

        Set the attachment mode to the specified value

        @param attachment: enable/disable attachment mode
        @type delay: C{bool}
        @return: None
        """

    def get_file_logging():
        """
        get_file_logging

        Return True if file logging mode is enabled, False otherwise.

        @return: boolean
        """

    def set_file_logging():
        """
        set_file_logging

        Enable file logging mode

        @return: None
        """

    def get_json_logging():
        """
        get_json_logging

        Return True if JSON logging mode is enabled, False otherwise.

        @return: boolean
        """

    def set_json_logging():
        """
        set_JSON_logging

        Enable JSON logging mode

        @return: None
        """

    def get_features_logging():
        """
        get_features_logging

        Return True if features logging mode is enabled, False otherwise.

        @return: boolean
        """

    def set_features_logging():
        """
        set_features_logging

        Enable features logging mode

        @return: None
        """

    def reset_features_logging():
        """
        reset_features_logging

        Reset features logging mode

        @return: None
        """

    def get_elasticsearch_logging():
        """
        get_elasticsearch_logging

        Return True if ElasticSearch logging mode is enabled, False otherwise.

        @return: boolean
        """

    def set_elasticsearch_logging():
        """
        set_elasticsearch_logging

        Enable ElasticSearch logging mode

        @return: None
        """

    def get_referer():
        """
        get_referer

        Return the emulated referer

        @return: referer value
        """

    def set_referer(referer):
        """
        set_referer

        Set the referer to be emulated

        @param referer: referer
        @type referer: C{str}
        @return: None
        """

    def get_proxy():
        """
        get_proxy

        Get the proxy server to be used for establishing the connection

        @return: proxy server
        """

    def set_proxy(proxy):
        """
        set_proxy

        Set the proxy server to be used for establishing the connection

        @param proxy: proxy server
        @type proxy: C{str}
        @return: None
        """

    def get_raise_for_proxy():
        """
        get_raise_for_proxy

        Get the raise_for_proxy flag. If the flag is True (default) a ValueError exception
        is raised if the specified proxy is not available.

        @return: boolean
        """

    def set_raise_for_proxy(raise_for_proxy):
        """
        set_raise_for_proxy

        Set the raise_for_proxy flag. If the flag is True (default) a ValueError exception
        is raised if the specified proxy is not available.

        @param raise_for_proxy: raise_for_proxy flag
        @type: raise_for_proxy: boolean
        @return: None
        """

    def set_no_fetch():
        """
        set_no_fetch

        Prevent remote content fetching in any case

        @return: None
        """

    def set_verbose():
        """
        set_verbose

        Enable Thug verbose mode

        @return: None
        """

    def set_debug():
        """
        set_debug

        Enable Thug debug mode

        @return: None
        """

    def set_ast_debug():
        """
        set_ast_debug

        Enable Thug AST debug mode

        @return: None
        """

    def set_http_debug():
        """
        set_http_debug

        Enable Thug HTTP debug mode

        @return: None
        """

    def set_acropdf_pdf(acropdf_pdf):
        """
        set_acropdf_pdf

        Set the Adobe Acrobat Reader version

        @param acropdf_pdf: Adobe Acrobat Reader version
        @type acropdf_pdf: C{str}
        @return: None
        """

    def disable_acropdf():
        """
        disable_acropdf

        Disable Adobe Acrobat Reader

        @return: None
        """

    def set_shockwave_flash(shockwave):
        """
        set_shockwave_flash

        Set the Shockwave Flash version (supported versions: 8, 9, 10, 11, 12)

        @param shockwave: Shockwave Flash version
        @type shockwave: C{str}
        @return: None
        """

    def disable_shockwave_flash():
        """
        disable_shockwave_flash

        Disable Shockwave Flash

        @return: None
        """

    def set_javaplugin(javaplugin):
        """
        set_javaplugin

        Set the Java plugin version

        @param javaplugin: Java plugin version
        @type javaplugin: C{str}
        @return: None
        """

    def disable_javaplugin():
        """
        disable_javaplugin

        Disable Java plugin

        @return: None
        """

    def set_silverlight(silverlight):
        """
        set_silverlight

        Set the SilverLight version

        @param silverlight: SilverLight version
        @type silverlight: C{str}
        @return: None
        """

    def disable_silverlight():
        """
        disable_silverlight

        Disable SilverLight

        @return: None
        """

    def get_threshold():
        """
        get_threshold

        Get the maximum number of pages to fetch

        @return: the maximum number of pages to fetch
        """

    def set_threshold(threshold):
        """
        set_threshold

        Set the maximum number of pages to fetch

        @param threshold: the maximum number of pages to fetch
        @type threshold: C{int}
        @return: None
        """

    def get_extensive():
        """
        get_extensive

        Get the current extensive fetch of linked pages mode

        @return: None
        """

    def set_extensive():
        """
        set_extensive

        Set the extensive fetch of linked pages mode

        @return: None
        """

    def get_connect_timeout():
        """
        get_connect_timeout

        Get the connect timeout (in seconds)

        @return: the connect timeout (in seconds)
        """

    def set_connect_timeout(timeout):
        """
        set_connect_timeout

        Set the connect timeout (in seconds)

        @param timeout: the connect timeout (in seconds)
        @type timeout: C{int}
        @return: None
        """

    def get_timeout():
        """
        get_timeout

        Get the analysis timeout (in seconds)

        @return: the analysis timeout (in seconds)
        """

    def set_timeout(timeout):
        """
        set_timeout

        Set the analysis timeout (in seconds)

        @param timeout: the analysis timeout (in seconds)
        @type timeout: C{int}
        @return: None
        """

    def get_broken_url():
        """
        get_broken_url

        Get the broken URL mode

        @return mode: broken URL mode
        """

    def set_broken_url():
        """
        set_broken_url

        Set the broken URL mode

        @return: None
        """

    def disable_honeyagent():
        """
        disable_honeyagent

        Disable HoneyAgent Java sandbox analysis

        @return: None
        """

    def enable_code_logging():
        """
        enable_code_logging

        Enable code logging

        @return: None
        """

    def disable_code_logging():
        """
        disable_code_logging

        Disable code logging

        @return: None
        """

    def enable_cert_logging():
        """
        enable_cert_logging

        Enable SSL/TLS certificate logging

        @return: None
        """

    def disable_cert_logging():
        """
        disable_cert_logging

        Disable SSL/TLS certificate logging

        @return: None
        """

    def log_init(url):
        """
        log_init

        Initialize logging subsystem

        @param url: URL to analyze
        @type url: C{str}
        @return: None
        """

    def set_log_dir(logdir):
        """
        set_log_dir

        Set the log output directory

        @param logdir: the log output directory
        @type logdir: C{str}
        @return: None
        """

    def set_log_output(output):
        """
        set_log_output

        Set the log output file

        @param output: the log output file
        @type output: C{str}
        @return: None
        """

    def set_log_quiet():
        """
        set_log_quiet

        Disable console logging

        @return: None
        """

    def set_vt_query():
        """
        set_vt_query

        Enable VirusTotal queries for sample analysis

        @return: None
        """

    def set_vt_submit():
        """
        set_vt_submit

        Enable VirusTotal samples submit

        @return: None
        """

    def get_web_tracking():
        """
        get_web_tracking

        Return True if web client tracking inspection is enabled, False otherwise.

        @return: bool
        """

    def set_web_tracking():
        """
        set_web_tracking

        Enable web client tracking inspection

        @return: None
        """

    def add_urlclassifier(rule):
        """
        add_urlclassifier

        Add an additional URL classifier rule file

        @param rule: URL classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_htmlclassifier(rule):
        """
        add_htmlclassifier

        Add an additional HTML classifier rule file

        @param rule: HTML classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_jsclassifier(rule):
        """
        add_jsclassifier

        Add an additional JS classifier rule file

        @param rule: JS classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_vbsclassifier(rule):
        """
        add_vbsclassifier

        Add an additional VBS classifier rule file

        @param rule: VBS classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_textclassifier(rule):
        """
        add_textclassifier

        Add an additional Text classifier rule file

        @param rule: Text classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_cookieclassifier(rule):
        """
        add_cookieclassifier

        Add an additional Cookie classifier rule file

        @param rule: Cookie classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_sampleclassifier(rule):
        """
        add_sampleclassifier

        Add an additional sample classifier rule file

        @param rule: Sample classifier rule file
        @type rule: C{str}
        @return: None
        """

    def add_urlfilter(filter):
        """
        add_urlfilter

        Add an additional URL filter file

        @param filter: URL filter file
        @type filter: C{str}
        @return: None
        """

    def add_htmlfilter(filter):
        """
        add_htmlfilter

        Add an additional HTML filter file

        @param filter: HTML filter file
        @type filter: C{str}
        @return: None
        """

    def add_jsfilter(filter):
        """
        add_jsfilter

        Add an additional JS filter file

        @param filter: JS filter file
        @type filter: C{str}
        @return: None
        """

    def add_vbsfilter(filter):
        """
        add_vbsfilter

        Add an additional VBS filter file

        @param filter: VBS filter file
        @type filter: C{str}
        @return: None
        """

    def add_textfilter(filter):
        """
        add_textfilter

        Add an additional Text filter file

        @param filter: Text filter file
        @type filter: C{str}
        @return: None
        """

    def add_cookiefilter(filter):
        """
        add_cookiefilter

        Add an additional Cookie filter file

        @param filter: Cookie filter file
        @type filter: C{str}
        @return: None
        """

    def add_samplefilter(filter):
        """
        add_samplefilter

        Add an additional sample filter file

        @param filter: Sample filter file
        @type filter: C{str}
        @return: None
        """

    def add_customclassifier(cls_type, method):
        """
        add_customclassifier

        Add a custom classifier.

        The parameter `cls_type' can assume the values

                html
                js
                vbs
                url
                text
                sample

        and defines the custom classifier scope.

        The parameter `method' is the method (not its name) to be additionaly invoked.
        The method parameters depend on the `cls_type' value and are listed here for
        convenience

                html    method(url, html)
                js      method(url, script)
                vbs     method(url, script)
                url     method(url)
                text    method(url, text)
                sample  method(sample, md5)

        @param cls_type: Classifier type
        @param cls_type: C{str}
        @param method: Classifier method
        @param method: method
        @return: None
        """

    def reset_customclassifiers():
        """
        reset_customclassifiers

        Reset all the custom classifiers

        @return: None
        """

    def log_event():
        """
        log_event

        Log the URL analysis results

        @return None
        """

    def run_local(url):
        """
        run_local

        This method should be invoked by 'analyze' method for local file analysis

        @param url: URL to analyze
        @type url: C{str}
        """

    def run_remote(url):
        """
        run_remote

        This method should be invoked by 'run' method for URL analysis

        @param url: URL to analyze
        @type url: C{str}
        """

    def analyze():
        """
        analyze

        This method is called when the ThugAPI subclass is called and MUST be
        implemented. This method can reference just the 'args' class attribute.
        Returning something from this method is up to you if needed.
        """
