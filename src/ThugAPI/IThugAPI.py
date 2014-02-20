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
        Supported values:
            winxpie60
            winxpie61
            winxpie70
            winxpie80
            winxpchrome20
            winxpfirefox12
            winxpsafari5
            win2kie60
            win2kie80
            win7ie80
            win7ie90
            win7chrome20
            win7safari5
            osx10safari5
            osx10chrome19
            galaxy2chrome18
            galaxy2chrome25
            linuxchrome26
            linuxfirefox19

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

        Get the proxy server to be used for estabilishing the connection

        @return: httplib2.ProxyInfo
        """

    def set_proxy(proxy):
        """
        set_proxy

        Set the proxy server to be used for estabilishing the connection

        @param proxy: proxy server
        @type proxy: C{str}
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

    def set_no_cache():
        """
        set_no_cache

        Disable local web cache

        @return: None
        """

    def set_ast_debug():
        """
        set_ast_debug

        Enable Thug AST debug mode

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

    def log_event():
        """
        log_event

        Log the URL analysis results

        @return None
        """

    def run(window):
        """
        run

        Method internally invoked by run_remote/run_local methods

        @param window: Window object
        @type window: Window
        @return: None
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
