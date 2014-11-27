# Thug


The number of client-side attacks has grown significantly in the past
few years shifting focus on poorly protected vulnerable clients. Just
as the most known honeypot technologies enable research into server-side
attacks, honeyclients allow the study of client-side attacks.

A complement to honeypots, a honeyclient is a tool designed to mimic
the behavior of a user-driven network client application, such as a web
browser, and be exploited by an attacker's content.

Thug is a Python low-interaction honeyclient aimed at mimicking the
behavior of a web browser in order to detect and emulate malicious
contents.


## Requirements

- Python 2.7 - http://www.python.org/

- Google V8 - http://code.google.com/p/v8/

- PyV8 - http://code.google.com/p/pyv8/

- Beautiful Soup 4 - http://www.crummy.com/software/BeautifulSoup/

- Html5lib - http://code.google.com/p/html5lib/

- Jsbeautifier - https://pypi.python.org/pypi/jsbeautifier

- Libemu - http://libemu.carnivore.it/

- Pylibemu 0.2.4 or later - https://github.com/buffer/pylibemu

- Pefile r141 or later - http://code.google.com/p/pefile/

- lxml - http://lxml.de/

- Chardet - http://pypi.python.org/pypi/chardet

- httplib2 0.7.4 or later - http://code.google.com/p/httplib2/

- Requests - https://github.com/kennethreitz/requests

- Cssutils 0.9.9 or later - http://pypi.python.org/pypi/cssutils/

- Zope interface - http://pypi.python.org/pypi/zope.interface

- Graphviz - http://www.graphviz.org/

- Pyparsing - http://pyparsing.wikispaces.com/

- Pydot - https://code.google.com/p/pydot/

- Python-Magic - https://github.com/ahupp/python-magic

- Rarfile - http://rarfile.berlios.de/

- Yara 2.0 - https://github.com/plusvic/yara

- Yara-Python 2.0 - https://github.com/plusvic/yara

- Boost - http://www.boost.org/

- NetworkX (optional) - https://networkx.github.io/

- MongoDB (optional) - http://www.mongodb.org/

- PyMongo (optional) - http://www.mongodb.org/display/DOCS/Python+Language+Center

- Ssdeep (optional) - http://ssdeep.sourceforge.net/

- Python-Ssdeep (optional) - https://github.com/DinoTools/python-ssdeep

- RabbitMQ (optional) - http://www.rabbitmq.com/

- Pika (optional) - https://github.com/pika/pika/


## Installation

### BeautifulSoup 4

If not available as a package for your Linux distribution, the best way
to install Beautiful Soup 4 is through `easy_install'. Beautiful Soup 4
is published through PyPi, so you can install it with easy_install or
pip. The package name is beautifulsoup4, and the same package works on
Python 2 and Python 3.

```# easy_install beautifulsoup4```

or alternatively

```# pip install beautifulsoup4```


### Boost

Boost provides free peer-reviewed portable C++ source libraries.
http://www.boost.org/
Boost packages should be available on most modern Linux systems. 



### V8/PyV8

In order to properly install V8 and PyV8 please follow the procedure
described below.


1. Checkout V8 source code from SVN

	```$ svn checkout http://v8.googlecode.com/svn/trunk/ v8```


2. Checkout PyV8 source code from SVN

	```$ svn checkout http://pyv8.googlecode.com/svn/trunk/ pyv8```

3. Patch PyV8 
	```
	$ cp thug/patches/PyV8-patch1.diff .
	$ patch -p0 < PyV8-patch1.diff 
	patching file pyv8/src/Context.cpp
	```

4. Set the environment variable V8_HOME with the V8 source code
   absolute path (you need to change the value reported below)

	```$ export V8_HOME=/home/buffer/v8```

5. Move to PyV8 source code directory

	```$ cd pyv8```

6. Build and install (PyV8 setup.py will properly install both V8
   and PyV8)

	```
	~/pyv8 $ python setup.py build
	~/pyv8 $ sudo python setup.py install
	```


In order to install the other required libraries and packages please
follow installation procedures as specified in their documentation.


## Usage

```
~/thug/src $ python thug.py -h

Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        python thug.py [ options ] url

    Options:
        -h, --help              Display this help information
        -V, --version           Display Thug version
        -u, --useragent=        Select a user agent (see below for values, default: winxpie60)
        -e, --events=           Enable comma-separated specified DOM events handling
        -w, --delay=            Set a maximum setTimeout/setInterval delay value (in milliseconds)
        -n, --logdir=           Set the log output directory
        -o, --output=           Log to a specified file
        -r, --referer=          Specify a referer
        -p, --proxy=            Specify a proxy (see below for format and supported schemes)
        -l, --local             Analyze a locally saved page
        -x, --local-nofetch     Analyze a locally saved page and prevent remote content fetching
        -v, --verbose           Enable verbose mode
        -d, --debug             Enable debug mode
        -q, --quiet             Disable console logging
        -m, --no-cache          Disable local web cache
        -a, --ast-debug         Enable AST debug mode (requires debug mode)
        -g, --http-debug        Enable HTTP debug mode
        -t, --threshold=        Maximum pages to fetch
        -E, --extensive         Extensive fetch of linked pages
        -T, --timeout=          Set the analysis timeout (in seconds)
		-B, --broken-url        Set the broken URL mode
		-y, --vtquery           Query VirusTotal for samples analysis
		-s, --vtsubmit          Submit samples to VirusTotal
		-N, --no-honeyagent     Disable HoneyAgent support

        Plugins:
        -A, --adobepdf=         Specify the Adobe Acrobat Reader version (default: 9.1.0)
        -P, --no-adobepdf       Disable Adobe Acrobat Reader plugin
        -S, --shockwave=        Specify the Shockwave Flash version (default: 10.0.64.0)
        -R, --no-shockwave      Disable Shockwave Flash plugin
        -J, --javaplugin=       Specify the JavaPlugin version (default: 1.6.0.32)
        -K, --no-javaplugin     Disable Java plugin

        Classifier:
        -Q, --urlclassifier     Specify a list of additional (comma separated) URL classifier rule files
        -W, --jsclassifier      Specify a list of additional (comma separated) JS classifier rule files
		-C, --sampleclassifier  Specify a list of additional (comma separated) sample classifier rule file

    Logging:
        -F, --file-logging      Enable file logging mode (default: disabled)
        -M, --maec11-logging    Enable MAEC11 logging mode (default: disabled)

    Proxy Format:
        scheme://[username:password@]host:port (supported schemes: http, http2, socks4, socks5)

    Available User-Agents:
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
```


## HPFeeds

HPFeeds is the Honeynet Project central logging feature and it is enabled by default
in Thug. If you don't want to report your events and samples, you can turn off HPFeeds
by modifying the configuration file src/Logging/logging.conf.

If you are interested in the data collected by Thug instances, please contact me at
<angelo.dellaera@honeynet.org>


## Support

* Mailing Lists
	* Thug users 	   https://public.honeynet.org/mailman/listinfo/thug
	* Thug development   https://public.honeynet.org/mailman/listinfo/thug-dev

* IRC
	* Freenode #thug-dev

Moreover take a look at http://buffer.github.com/thug/ for additional details
and documentation about the project. If you appreciate Thug please consider
making a donation using Paypal (details at http://buffer.github.com/thug/).


## License information

Copyright (C) 2011-2014 Angelo Dell'Aera <buffer@antifork.org>

License: GNU General Public License, version 2 or later; see COPYING.txt
         included in this archive for details.
