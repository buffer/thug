.. _build:

Build and Install
=================

Requirements
------------

* Python
* Google V8                
* PyV8                     
* Beautiful Soup 4         
* Html5lib
* Jsbeautifier
* Libemu                   
* Pylibemu
* Pefile
* lxml
* Chardet                  
* Requests
* Requesocks
* boost
* Cssutils
* Zope interface
* Graphviz
* Pyparsing
* Pygraphviz
* Python-Magic
* Rarfile
* Yara 2.0
* Yara-Python 2.0
* NetworkX (optional)
* MongoDB (optional)
* PyMongo (optional)
* Androguard (optional)
* Ssdeep (optional)
* Python-Ssdeep (optional)
* RabbitMQ (optional)
* Pika (optional)


Installation
------------


Python
^^^^^^

Python 2.7 is required in order to properly run Thug. You may be lucky running it with
Python 2.6 but please consider that it is not supported so issues related to Python 2.6
will be simply ignored. Python source code can be downloaded at http://www.python.org.


Google V8/PyV8
^^^^^^^^^^^^^^
  
Google V8 is Google's open source JavaScript engine. V8 is written in C++ and is used
in Google Chrome, the open source browser from Google. V8 implements ECMAScript as 
specified in ECMA-262, 3rd edition, and runs on Windows XP and Vista, Mac OS X 10.5 
(Leopard), and Linux systems that use IA-32 or ARM processors. V8 can run standalone, 
or can be embedded into any C++ application.  

PyV8 is a Python wrapper for the Google V8 engine. PyV8 acts as a bridge between the 
Python and JavaScript objects and supports the Google V8 engine in Python scripts.

In order to properly install Google V8 and PyV8 please follow the procedure described 
below.

1. Checkout V8 source code from SVN

.. code-block:: sh

        $ svn checkout http://v8.googlecode.com/svn/trunk/ v8

2. Checkout PyV8 source code from SVN

.. code-block:: sh

        $ svn checkout http://pyv8.googlecode.com/svn/trunk/ pyv8

3. Patch PyV8 

.. code-block:: sh

	$ cp thug/patches/PyV8-patch1.diff .
	$ patch -p0 < PyV8-patch1.diff
	patching file pyv8/src/Context.cpp
	$

4. Set the environment variable V8_HOME with the V8 source code
   absolute path (you need to change the value reported below)

.. code-block:: sh

        $ export V8_HOME=/home/buffer/v8

5. Move to PyV8 source code directory

.. code-block:: sh

        $ cd pyv8

6. Build and install (PyV8 setup.py will properly install both V8
   and PyV8)

.. code-block:: sh

        ~/pyv8 $ python setup.py build
        ~/pyv8 $ sudo python setup.py install


Beautiful Soup 4
^^^^^^^^^^^^^^^^

Beautiful Soup is a Python library for pulling data out of HTML and XML 
files. Beautiful Soup source code can be downloaded at 
http://www.crummy.com/software/BeautifulSoup/.

If not available as a package for your Linux distribution, the best way 
to install Beautiful Soup 4 is through pip.

.. code-block:: sh

        # pip install beautifulsoup4  

 
html5lib
^^^^^^^^

html5lib is a Python and PHP implementations of a HTML parser based on the 
WHATWG HTML5 specification for maximum compatibility with major desktop 
web browsers. html5lib source code can be downloaded at 
http://code.google.com/p/html5lib/.

If not available as a package for your Linux distribution, the best way 
to install html5lib is through pip. 

.. code-block:: sh

        # pip install html5lib 


Jsbeautifier
^^^^^^^^^^^^

Jsbeautifier beautifies, unpacks or deobfuscates JavaScript and handles 
popular online obfuscators. jsbeautifier code can be downloaded at
https://github.com/einars/js-beautify

If not available as a package for your Linux distribution, the best way
to install jsbeautifier is through pip.

.. code-block:: sh

        # pip install jsbeautifier 


Libemu
^^^^^^

Libemu is a small library written in C offering basic x86 emulation and 
shellcode detection using GetPC heuristics. It is designed to be used 
within network intrusion/prevention detections and honeypots. Libemu 
homepage is located at http://libemu.carnivore.it/.

In order to properly install Libemu please follow the procedure described
below

.. code-block:: sh

        $ git clone git://github.com/buffer/libemu.git
        $ cd libemu
        $ autoreconf -v -i
        $ ./configure --prefix=/opt/libemu
        $ sudo make install

For additional details about installation please refer to the Libemu homepage.


Pylibemu
^^^^^^^^

Pylibemu is a Cython wrapper for the Libemu library. Pylibemu homepage is located
at https://github.com/buffer/pylibemu.

Pylibemu 0.2.4 or later is strictly required.

In order to properly install Pylibemu please follow the procedure described
below

.. code-block:: sh
        
        $ git clone git://github.com/buffer/pylibemu.git
        $ python setup.py build
        $ sudo python setup.py install

For additional details about installation please refer to the Pylibemu homepage.


Pefile
^^^^^^

Pefile is a multi-platform Python module to read and work with Portable Executable 
(aka PE) files. Most of the information in the PE Header is accessible, as well as 
all the sections, section's information and data. Pefile homepage is located at
http://code.google.com/p/pefile/.

Pefile r141 or later is strictly required.

If not available as a package for your Linux distribution, the best way
to install Pefile is through pip.

.. code-block:: sh

        # pip install pefile 


lxml
^^^^

The lxml XML toolkit is a Pythonic binding for the C libraries libxml2 and libxslt.
It is unique in that it combines the speed and XML feature completeness of these
libraries with the simplicity of a native Python API, mostly compatible but superior
to the well-known ElementTree API.

If not available as a package for your Linux distribution, the best way
to install lxml is through pip.

.. code-block:: sh

        # pip install lxml


chardet
^^^^^^^

Chardet is a universal encoding detector. Chardet homepage is located at
http://pypi.python.org/pypi/chardet.

If not available as a package for your Linux distribution, the best way
to install chardet is through pip.

.. code-block:: sh

        # pip install chardet  


Requests
^^^^^^^^

Requests is an Apache2 Licensed HTTP library, written in Python, for human
beings. Requests homepage is located at
http://docs.python-requests.org/en/latest/

If not available as a package for your Linux distribution, the best way
to install requests is through pip.

.. code-block:: sh

        # pip install requests


PySocks
^^^^^^^

PySocks is an actively maintained SocksiPy fork. It contains many improvements to 
the original. PySocks homepage is located at https://github.com/Anorov/PySocks.

If not available as a package for your Linux distribution, the best way
to install requests is through pip.

.. code-block:: sh

        # pip install PySocks


Boost
^^^^^

Boost provides free peer-reviewed portable C++ source libraries. Boost homepage is 
located at http://www.boost.org/. Packages for most Linux distributions are provided.


Cssutils
^^^^^^^^

Cssutils is a CSS Cascading Style Sheets library for Python. Cssutils homepage
is located at http://pypi.python.org/pypi/cssutils.

If not available as a package for your Linux distribution, the best way
to install cssutils is through pip.

Cssutils 0.9.9 or later is strictly required.

.. code-block:: sh

        # pip install cssutils


Zope Interface
^^^^^^^^^^^^^^

Zope Interface homepage is located at http://pypi.python.org/pypi/zope.interface.

If not available as a package for your Linux distribution, the best way
to install zope.interface is through pip.

.. code-block:: sh

        # pip install zope.interface


Graphviz
^^^^^^^^

Graphviz homepage is located at http://www.graphviz.org/.

Graphviz is open source graph visualization software. Graph visualization is a way of representing 
structural information as diagrams of abstract graphs and networks. It has important applications 
in networking, bioinformatics, software engineering, database and web design, machine learning, 
and in visual interfaces for other technical domains.

If not available as a package for your Linux distribution, change distribution!


Pyparsing
^^^^^^^^^

Pyparsing homepage is located at http://pyparsing.wikispaces.com/.

If not available as a package for your Linux distribution, the best way 
to install pyparsing is through pip.

.. code-block:: sh

        # pip install pyparsing


Pygraphviz
^^^^^^^^^^

Pydot homepage is located at http://pygraphviz.github.io.

If not available as a package for your Linux distribution, the best way
to install pydot is through pip.

.. code-block:: sh

        # pip install pygraphviz


Python-Magic
^^^^^^^^^^^^

The recommended implementation of python-magic can be found at 
https://github.com/ahupp/python-magic.

The best way to install python-magic is through pip.

.. code-block:: sh

        # pip install python-magic

If you are running Ubuntu, you may want to use a completely different
implementation of python-magic which is packaged through apt.

.. code-block:: sh

        # apt-get install python-magic


Rarfile
^^^^^^^

Rarfile homepage is located at http://rarfile.berlios.de/.

If not available as a package for your Linux distribution, the best way 
to install rarfile is through pip.

.. code-block:: sh

        # pip install rarfile


Yara
^^^^

Yara homepage is located at https://github.com/plusvic/yara

If not available as a package for your Linux distribution, the best way
to install Yara is compiling its source code. Please take a look at Yara
documentation for details.


Yara-Python
^^^^^^^^^^^

Yara-Python homepage is located at https://github.com/plusvic/yara

If not available as a package for your Linux distribution, the best way
to install Yara-Python is compiling its source code. Please take a look 
at Yara-Python documentation for details.


NetworkX (optional)
^^^^^^^^^^^^^^^^^^^

NetworkX homepage is located at https://networkx.github.io/
 
NetworkX is a Python language software package for the creation, manipulation, 
and study of the structure, dynamics, and functions of complex networks.

If not available as a package for your Linux distribution, the best way 
to install networkx is through pip.

.. code-block:: sh

        # pip install networkx


MongoDB (optional)
^^^^^^^^^^^^^^^^^^

MongoDB homepage is located at http://www.mongodb.org.

If not available as a package for your Linux distribution, change distribution!


PyMongo (optional)
^^^^^^^^^^^^^^^^^^

PyMongo homepage is located at http://www.mongodb.org/display/DOCS/Python+Language+Center.

If not available as a package for your Linux distribution, the best way
to install pymongo is through pip.

.. code-block:: sh

        # pip install pymongo  


Androguard (optional)
^^^^^^^^^^^^^^^^^^^^^

Androguard is a tool useful for Android applications static analysis. Androguard homepage
is located at https://github.com/androguard/androguard.

If not available as a package for your Linux distribution, the best way to install Androguard
is the one shown below

.. code-block:: sh

        # git clone git@github.com:androguard/androguard.git
        # cd androguard
        # python setup.py install


Ssdeep (optional)
^^^^^^^^^^^^^^^^^

Ssdeep is a program for computing context triggered piecewise hashes (CTPH). Also called 
fuzzy hashes, CTPH can match inputs that have homologies. Such inputs have sequences of 
identical bytes in the same order, although bytes in between these sequences may be 
different in both content and length.

Packages for most Linux distributions are provided.


Python-Ssdeep (optional)
^^^^^^^^^^^^^^^^^^^^^^^^

Python-Ssdeep homepage is located at https://github.com/DinoTools/python-ssdeep.

If not available as a package for your Linux distribution, the best way
to install python-ssdeep is through pip.

.. code-block:: sh

        # pip install ssdeep


RabbitMQ (optional)
^^^^^^^^^^^^^^^^^^^

RabbitMQ homepage is located at http://www.rabbitmq.com/. RabbitMQ is a high-performance 
AMQP-compliant message broker written in Erlang and it's needed just if you want to play
with Thug distributed mode.

If not available as a package for your Linux distribution, change distribution!


Pika (optional)
^^^^^^^^^^^^^^^

Pika homepage is located at https://github.com/pika/pika/.

Pika is a pure-Python implementation of the AMQP 0-9-1 protocol that tries to stay fairly 
independent of the underlying network support library and it's needed just if you want to play
with Thug distributed mode.

If not available as a package for your Linux distribution, the best way
to install pika is through pip.

.. code-block:: sh

    # pip install pika
