.. _usage:

Usage
==========================

.. toctree::
   :maxdepth: 2


Basic usage
-----------

.. code-block:: sh

        ~/thug/src $ python thug.py -h

        Synopsis:
                Thug: Pure Python honeyclient implementation

                Usage:
                        python thug.py [ options ] url

                Options:
                        -h, --help              Display this help information
                        -o, --output=           Log to a specified file
                        -r, --referer=          Specify a referer
                        -p, --proxy=            Specify a proxy (see below for format and supported schemes)
                        -l, --local         
                        -v, --verbose           Enable verbose mode    
                        -d, --debug             Enable debug mode
                        -a, --ast-debug         Enable AST debug mode (requires debug mode) 
                        -u, --useragent=        Select a user agent (see below for values, default: xpie61)

                Proxy Format:
                        scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)

                Available User-Agents:
                        xpie60                  Internet Explorer 6.0 (Windows XP)
                        xpie61                  Internet Explorer 6.1 (Windows XP)
                        xpie70                  Internet Explorer 7.0 (Windows XP)
                        xpie80                  Internet Explorer 8.0 (Windows XP)
                        w2kie60                 Internet Explorer 6.0 (Windows 2000)
                        w2kie80                 Internet Explorer 8.0 (Windows 2000)

