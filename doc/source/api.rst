.. _api:

Thug API
========


Thug provides a Python Application Program Interface (API) which allows external tools
easily interfacing with Thug. Basic usage of the Thug API is really simple and just
requires subclassing the ThugAPI class. Thug class (defined in *src/thug.py*) is a
great example of such usage which should be enough in almost every scenario I can think
about.

Thug API interface definition is reported below for convenience.


.. code-block:: python


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

                winxpie60               Internet Explorer 6.0   (Windows XP)
                winxpie61               Internet Explorer 6.1   (Windows XP)
                winxpie70               Internet Explorer 7.0   (Windows XP)
                winxpie80               Internet Explorer 8.0   (Windows XP)
                winxpchrome20           Chrome 20.0.1132.47     (Windows XP)
                winxpfirefox12          Firefox 12.0            (Windows XP)
                winxpsafari5            Safari 5.1.7            (Windows XP)
                win2kie60               Internet Explorer 6.0   (Windows 2000)
                win2kie80               Internet Explorer 8.0   (Windows 2000)
                win7ie80                Internet Explorer 8.0   (Windows 7)
                win7ie90                Internet Explorer 9.0   (Windows 7)
                win7chrome20            Chrome 20.0.1132.47     (Windows 7)
                win7firefox3            Firefox 3.6.13          (Windows 7)
                win7safari5             Safari 5.1.7            (Windows 7)
                osx10safari5            Safari 5.1.1            (MacOS X 10.7.2)
                osx10chrome19           Chrome 19.0.1084.54     (MacOS X 10.7.4)
                linuxchrome26           Chrome 26.0.1410.19     (Linux)
                linuxchrome30           Chrome 30.0.1599.15     (Linux)
                linuxfirefox19          Firefox 19.0            (Linux)
                galaxy2chrome18         Chrome 18.0.1025.166    (Samsung Galaxy S II, Android 4.0.3)
                galaxy2chrome25         Chrome 25.0.1364.123    (Samsung Galaxy S II, Android 4.0.3)
                galaxy2chrome29         Chrome 29.0.1547.59     (Samsung Galaxy S II, Android 4.1.2)
                nexuschrome18           Chrome 18.0.1025.133    (Google Nexus, Android 4.0.4)
                ipadsafari7             Safari 7.0              (iPad, iOS 7.0.4)
                ipadsafari8             Safari 8.0              (iPad, iOS 8.0.2)
                ipadchrome33            Chrome 33.0.1750.21     (iPad, iOS 7.1)
                ipadchrome35            Chrome 35.0.1916.41     (iPad, iOS 7.1.1)
                ipadchrome37            Chrome 37.0.2062.52     (iPad, iOS 7.1.2)
                ipadchrome38            Chrome 38.0.2125.59     (iPad, iOS 8.0.2)
                ipadchrome39            Chrome 39.0.2171.45     (iPad, iOS 8.1.1)

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

        def get_maec11_logging():
            """
            get_maec11_logging

            Return True if MAEC 1.1 logging mode is enabled, False otherwise.

            @return: boolean
            """

        def set_maec11_logging():
            """
            set_maec11_logging

            Enable MAEC 1.1 logging mode

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

            @return: proxy server
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

        def get_mongodb_instance():
            """
            get_mongodb_instance

            Get the address ("host:port") of the MongoDB instance specified at runtime
            (not the one from the logging.conf file)

            @return: None
            """

        def set_mongodb_instance():
            """
            set_mongodb_instance

            Set the address ("host:port") of a running MongoDB instance to be used at runtime

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

        def add_jsclassifier(rule):
            """
            add_jsclassifier

            Add an additional JS classifier rule file

            @param rule: JS classifier rule file
            @type rule: C{str}
            @return: None
            """

        def add_sampleclassifier(rule):
            """
            add_sampleclassifier

            Add an additional Sample classifier rule file

            @param rule: Sample classifier rule file
            @type rule: C{str}
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
