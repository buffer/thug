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
* Chardet                  
* httplib2 
* Cssutils
* Zope interface
* Graphviz
* Pyparsing
* Pydot
* Python-Magic
* Yara
* Yara-Python
* MongoDB (optional)       
* PyMongo (optional)       
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

3. Set the environment variable V8_HOME with the V8 source code
   absolute path (you need to change the value reported below)

.. code-block:: sh

        $ export V8_HOME=/home/buffer/v8

4. Move to PyV8 source code directory

.. code-block:: sh

        $ cd pyv8

5. Build and install (PyV8 setup.py will properly install both V8
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
to install Beautiful Soup 4 is through easy_install.

.. code-block:: sh

        # easy_install beautifulsoup4  

 
html5lib
^^^^^^^^

html5lib is a Python and PHP implementations of a HTML parser based on the 
WHATWG HTML5 specification for maximum compatibility with major desktop 
web browsers. html5lib source code can be downloaded at 
http://code.google.com/p/html5lib/.

If not available as a package for your Linux distribution, the best way 
to install html5lib is through easy_install. 

.. code-block:: sh

        # easy_install html5lib 


Jsbeautifier
^^^^^^^^^^^^

Jsbeautifier beautifies, unpacks or deobfuscates JavaScript and handles 
popular online obfuscators. jsbeautifier code can be downloaded at
https://github.com/einars/js-beautify

If not available as a package for your Linux distribution, the best way
to install jsbeautifier is through easy_install.

.. code-block:: sh

        # easy_install jsbeautifier 


Libemu
^^^^^^

Libemu is a small library written in C offering basic x86 emulation and 
shellcode detection using GetPC heuristics. It is designed to be used 
within network intrusion/prevention detections and honeypots. Libemu 
homepage is located at http://libemu.carnivore.it/.

In order to properly install Libemu please follow the procedure described
below

.. code-block:: sh

        $ git clone git://git.carnivore.it/libemu.git
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

If not available as a package for your Linux distribution, the best way
to install Pefile is through easy_install.

.. code-block:: sh

        # easy_install pefile 


chardet
^^^^^^^

Chardet is a universal encoding detector. Chardet homepage is located at
http://pypi.python.org/pypi/chardet.

If not available as a package for your Linux distribution, the best way
to install chardet is through easy_install.

.. code-block:: sh

        # easy_install chardet  


httplib2
^^^^^^^^

Httplib2 is a comprehensive HTTP client library that supports many features 
left out of other HTTP libraries. Httplib2 homepage is located at 
http://code.google.com/p/httplib2/

Httplib 0.7.4 or later is strictly required.

If not available as a package for your Linux distribution, the best way
to install httplib2 is through easy_install.

.. code-block:: sh

        # easy_install httplib2


Cssutils
^^^^^^^^

Cssutils is a CSS Cascading Style Sheets library for Python. Cssutils homepage
is located at http://pypi.python.org/pypi/cssutils.

If not available as a package for your Linux distribution, the best way
to install cssutils is through easy_install.

Cssutils 0.9.9 or later is strictly required.

.. code-block:: sh

        # easy_install cssutils


Zope Interface
^^^^^^^^^^^^^^

Zope Interface homepage is located at http://pypi.python.org/pypi/zope.interface.

If not available as a package for your Linux distribution, the best way
to install zope.interface is through easy_install.

.. code-block:: sh

        # easy_install zope.interface


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
to install pyparsing is through easy_install.

.. code-block:: sh

        # easy_install pyparsing


Pydot
^^^^^

Pydot homepage is located at https://code.google.com/p/pydot/.

If not available as a package for your Linux distribution, the best way
to install pydot is through easy_install.

.. code-block:: sh

        # easy_install pydot


Python-Magic
^^^^^^^^^^^^

Python-Magic homepage is located at https://github.com/ahupp/python-magic.

If not available as a package for your Linux distribution, the best way
to install python-magic is through easy_install.

.. code-block:: sh

        # easy_install magic


Yara
^^^^

Yara homepage is located at https://code.google.com/p/yara-project/

If not available as a package for your Linux distribution, the best way
to install Yara is compiling its source code. Please take a look at Yara
documentation for details.


Yara-Python
^^^^^^^^^^^

Yara-Python homepage is located at https://code.google.com/p/yara-project/

If not available as a package for your Linux distribution, the best way
to install Yara-Python is compiling its source code. Please take a look 
at Yara-Python documentation for details.


MongoDB (optional)
^^^^^^^^^^^^^^^^^^

MongoDB homepage is located at http://www.mongodb.org.

If not available as a package for your Linux distribution, change distribution!


PyMongo (optional)
^^^^^^^^^^^^^^^^^^

PyMongo homepage is located at http://www.mongodb.org/display/DOCS/Python+Language+Center.

If not available as a package for your Linux distribution, the best way
to install pymongo is through easy_install.

.. code-block:: sh

        # easy_install pymongo  


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
to install pika is through easy_install.

.. code-block:: sh

    # easy_install pika
