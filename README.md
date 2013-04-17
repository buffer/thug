
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

### Application Packages

- Setup Tools - https://pypi.python.org/pypi/setuptools

- Graphviz - http://www.graphviz.org/

- Git - http://git-scm.com

- Autoconf - http://www.gnu.org/software/autoconf/

- Python-dev - http://python.org

- Subversion - http://subversion.apache.org

- gcc & g++ - http://gcc.gnu.org

### Python Packages

- Pip - https://pypi.python.org/pypi/pip

- Beautiful Soup 4 - http://www.crummy.com/software/BeautifulSoup/

- Pefile - http://code.google.com/p/pefile/

- Requests - http://docs.python-requests.org/en/latest/

- Chardet - http://pypi.python.org/pypi/chardet

- httplib2 0.7.4 or later - http://code.google.com/p/httplib2/

- Cssutils - http://pypi.python.org/pypi/cssutils/

- Zope interface - http://pypi.python.org/pypi/zope.interface

- Pyparsing - http://pyparsing.wikispaces.com/

- Pydot - https://code.google.com/p/pydot/

- Python-Magic - https://github.com/ahupp/python-magic

### Manually Installed

- Python 2.7 - http://www.python.org/

- Google V8 - http://code.google.com/p/v8/

- PyV8 - http://code.google.com/p/pyv8/

- Html5lib - http://code.google.com/p/html5lib/

- Libemu - http://libemu.carnivore.it/

- Pylibemu 0.2.4 or later - https://github.com/buffer/pylibemu

## Optional

- MongoDB (optional) - http://www.mongodb.org/

- PyMongo (optional) - http://www.mongodb.org/display/DOCS/Python+Language+Center

- RabbitMQ (optional) - http://www.rabbitmq.com/

- Pika (optional) - https://github.com/pika/pika/


## Installation

To start move into tmp and pull the Thug source:

```
$ cd /tmp
$ git clone git://github.com/buffer/thug.git
```

### Apt-get

```$ apt-get install graphviz python-setuptools git autoconf python-dev libtool build-essentials subversion gcc g++ libboost-python-dev```

Pip is the easiest way to install Thug's required Python packages. Install pip with:

```$ easy_install pip```

### Python Packages

```$ pip install beautifulsoup4 pefile requests chardet httplib2 cssutils zope.interface pyparsing==1.5.7 pydot python-magic```

### Libemu & Pylibemu

Download and install libemu with the following (based on [directions from Xanda](http://blog.xanda.org/2012/05/16/installation-of-libemu-and-pylibemu-on-ubuntu/)):
```
$ git clone git://git.carnivore.it/libemu.git
$ cd libemu
$ autoreconf -v -i
$ ./configure --enable-python-bindings --prefix=/opt/libemu
$ sudo make install
$ sudo ldconfig -n /opt/libemu/lib
```

Download and install pylibemu [Buffer/pylibemu](https://github.com/buffer/pylibemu):
```
$ git clone git://github.com/buffer/pylibemu.git
$ cd pylibemu
$ sudo sh -c "echo /opt/libemu/lib/ > /etc/ld.so.conf.d/pylibemu.conf"
$ python setup.py build
$ sudo python setup.py install
$ sudo ldconfig
```

### V8/PyV8

In order to properly install V8 and PyV8 please follow the procedure
described below.


1. Checkout V8 -r14110 source code from SVN:

	```$ svn checkout -r14110 http://v8.googlecode.com/svn/trunk/ v8```

2. Patch V8 source code with the patches you can find in thug/patches
   directory:

	```
	$ cp thug/patches/V8-patch* .
	$ patch -p0 < V8-patch1.diff
	```

3. Checkout PyV8 -r478 source code from SVN:

	```$ svn checkout -r478 http://pyv8.googlecode.com/svn/trunk/ pyv8```

4. Set the environment variable V8_HOME with the V8 source code
   absolute path (you need to change the value reported below):

	```$ export V8_HOME=/tmp/v8```

5. Move to PyV8 source code directory:

	```$ cd pyv8```

6. Edit setup.py file and comment line 466 as shown:

	```python
	#checkout_v8()
	```

7. Build and install (PyV8 setup.py will properly install both V8
   and PyV8):

	```
	$ python setup.py build
	$ sudo python setup.py install
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
