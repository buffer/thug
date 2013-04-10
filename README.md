
# Thug


The number of client-side attacks has grown significantly in the past
few years shifting focus on poorly protected vulnerable clients. Just
as the most known honeypot technologies enable research into server-side
attacks, honeyclients allow the study of client-side attacks.

A complement to honeypots, a honeyclient is a tool designed to mimic
the behavior of a user-driven network client application, such as a web
browser, and be exploited by an attacker's content.

Thug is a Python low-interaction honeyclient aimed at mimicing the
behavior of a web browser in order to detect and emulate malicious
contents.


## Requirements

- Python 2.7 - http://www.python.org/

- Google V8 - http://code.google.com/p/v8/

- PyV8 - http://code.google.com/p/pyv8/

- Beautiful Soup 4 - http://www.crummy.com/software/BeautifulSoup/

- Html5lib - http://code.google.com/p/html5lib/

- Libemu - http://libemu.carnivore.it/

- Pylibemu 0.2.4 or later - https://github.com/buffer/pylibemu

- Pefile - http://code.google.com/p/pefile/

- Chardet - http://pypi.python.org/pypi/chardet

- httplib2 0.7.4 or later - http://code.google.com/p/httplib2/

- Cssutils - http://pypi.python.org/pypi/cssutils/

- Zope interface - http://pypi.python.org/pypi/zope.interface

- Graphviz - http://www.graphviz.org/

- Pyparsing - http://pyparsing.wikispaces.com/

- Pydot - https://code.google.com/p/pydot/

- Python-Magic - https://github.com/ahupp/python-magic

- MongoDB (optional) - http://www.mongodb.org/

- PyMongo (optional) - http://www.mongodb.org/display/DOCS/Python+Language+Center

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


### V8/PyV8

In order to properly install V8 and PyV8 please follow the procedure
described below.


1. Checkout V8 -r14110 source code from SVN

	```$ svn checkout -r14110 http://v8.googlecode.com/svn/trunk/ v8```

2. Patch V8 source code with the patches you can find in thug/patches
   directory

	```$ cp thug/patches/V8-patch* .
	$ patch -p0 < V8-patch1.diff
	patching file v8/src/log.h```

3. Checkout PyV8 -r478 source code from SVN

	```$ svn checkout -r478 http://pyv8.googlecode.com/svn/trunk/ pyv8```

4. Set the environment variable V8_HOME with the V8 source code
   absolute path (you need to change the value reported below)

	```$ export V8_HOME=/home/buffer/v8```

5. Move to PyV8 source code directory

	```$ cd pyv8```

6. Edit PyV8.py setup.py file and comment line 466 as shown

	```#checkout_v8()```

7. Build and install (PyV8 setup.py will properly install both V8
   and PyV8)

	```~/pyv8 $ python setup.py build
	~/pyv8 $ sudo python setup.py install```


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
        -t, --threshold         Maximum pages to fetch
        -E, --extensive         Extensive fetch of linked pages
        -T, --timeout           Timeout in minutes

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
        win7safari5             Safari 5.1.7            (Windows 7)
        osx10safari5            Safari 5.1.1            (MacOS X 10.7.2)
        osx10chrome19           Chrome 19.0.1084.54     (MacOS X 10.7.4)
        galaxy2chrome18         Chrome 18.0.1025.166    (Samsung Galaxy S II, Android 4.0.3)
        galaxy2chrome25         Chrome 25.0.1364.123    (Samsung Galaxy S II, Android 4.0.3)
        linuxchrome26           Chrome 26.0.1410.19     (Linux)
        linuxfirefox19          Firefox 19.0            (Linux)
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

Copyright (C) 2011-2013 Angelo Dell'Aera <buffer@antifork.org>

License: GNU General Public License, version 2 or later; see COPYING.txt
         included in this archive for details.
