.. _build:

Build and Install
=================

Requirements
------------

* Python
* Boost
* Google V8                
* PyV8
* MongoDB (optional)
* Graphviz
* RabbitMQ (optional)
* BeautifulSoup4
* Html5lib
* Libemu/Pylibemu
* PEfile
* Yara
* Yara-Python
* Lxml
* cChardet
* Requests
* PySocks
* Cssutils
* Zope interface
* Pygraphviz
* Python-Magic
* Rarfile
* NetworkX (optional)
* PyMongo (optional)
* Python-Ssdeep (optional)


Installation
------------


Python
^^^^^^

Python 2.7 is required in order to properly run Thug. You may be lucky running it with
Python 2.6 but please consider this version is not supported so issues related to Python 
2.6 will be simply ignored. Python source code can be downloaded at http://www.python.org.


Boost
^^^^^

Boost provides free peer-reviewed portable C++ source libraries. Boost homepage is
located at http://www.boost.org/. 

Packages for most Linux distributions are available.


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

.. code-block:: sh

        $ git clone https://github.com/buffer/pyv8.git
        $ cd pyv8
        ~/pyv8 $ python setup.py build
        ~/pyv8 $ sudo python setup.py install


MongoDB (optional)
^^^^^^^^^^^^^^^^^^

MongoDB homepage is located at http://www.mongodb.org.

Packages for most Linux distributions are available.
 

Graphviz
^^^^^^^^

Graphviz homepage is located at http://www.graphviz.org/.

Graphviz is open source graph visualization software. Graph visualization is a way of representing
structural information as diagrams of abstract graphs and networks. It has important applications
in networking, bioinformatics, software engineering, database and web design, machine learning,
and in visual interfaces for other technical domains.

Packages for most Linux distributions are available.


RabbitMQ (optional)
^^^^^^^^^^^^^^^^^^^

RabbitMQ homepage is located at http://www.rabbitmq.com/. RabbitMQ is a high-performance
AMQP-compliant message broker written in Erlang and it's needed just if you want to play
with Thug distributed mode.

Packages for most Linux distributions are available.



Thug installation
-----------------

Starting from Thug 0.8.0, Thug is installable through pip with the following procedure 

.. code-block:: sh

	# pip install thug

Alternatively you can clone the Thug repository and install it executing

.. code-block:: sh

    $ cd thug
    $ python setup.py build
    $ sudo python setup.py install


The procedure will install the dependencies not already mentioned in the previous sections so you 
should take care of installing them before actually installing Thug.

You are strongly encouraged to install such dependencies using this procedure. In such case you
can skip the following sections, otherwise keep on reading.  


BeautifulSoup4
^^^^^^^^^^^^^^

BeautifulSoup4 is a Python library for pulling data out of HTML and XML files. BeautifulSoup4 source 
code can be downloaded at http://www.crummy.com/software/BeautifulSoup/.

If not available as a package for your Linux distribution, the best way to install BeautifulSoup4 is 
through pip.

.. code-block:: sh

        # pip install beautifulsoup4  

 
Html5lib
^^^^^^^^

Html5lib is a Python and PHP implementations of a HTML parser based on the WHATWG HTML5 specification 
for maximum compatibility with major desktop web browsers. Html5lib source code can be downloaded at 
http://code.google.com/p/html5lib/.

If not available as a package for your Linux distribution, the best way to install html5lib is through 
pip. 

.. code-block:: sh

        # pip install html5lib 


Libemu/Pylibemu
^^^^^^^^^^^^^^^

Libemu is a small library written in C offering basic x86 emulation and 
shellcode detection using GetPC heuristics. It is designed to be used
within network intrusion/prevention detections and honeypots. Libemu
homepage is located at http://libemu.carnivore.it/.

Pylibemu is a Cython wrapper for the Libemu library. Pylibemu homepage is 
located at https://github.com/buffer/pylibemu.

The best way to install Pylibemu is through pip (which will take care of
installing and configuring Libemu too).

.. code-block:: sh

        # pip install pylibemu

Alternatively follow the procedure described below

.. code-block:: sh
        
        $ git clone --recursive https://github.com/buffer/pylibemu.git
        $ sudo python setup.py install

For additional details about installation please refer to the Pylibemu homepage.


PEfile
^^^^^^

PEfile is a multi-platform Python module to read and work with Portable Executable (aka PE) files. 
Most of the information in the PE Header is accessible, as well as all the sections, section's 
information and data. PEfile homepage is located at https://github.com/erocarrera/pefile.

If not available as a package for your Linux distribution, the best way to install PEfile is through
pip.

.. code-block:: sh

	# pip install pefile

Alternatively follow the procedure described below

.. code-block:: sh

	$ git clone https://github.com/erocarrera/pefile.git
	$ python setup.py build
	$ sudo python setup.py install

Yara
^^^^

Yara homepage is located at https://github.com/plusvic/yara

If not available as a package for your Linux distribution, the best way
to install Yara is compiling its source code. Please take a look at the 
following paragraph about Yara-Python for additional details.
documentation for details.


Yara-Python
^^^^^^^^^^^

Yara-Python homepage is located at https://github.com/plusvic/yara-python

If not available as a package for your Linux distribution, the best way
to install Yara-Python is compiling its source code with the following 
procedure 

.. code-block:: sh

	$ git clone --recursive https://github.com/plusvic/yara-python
	$ cd yara-python
	$ python setup.py build
	$ sudo python setup.py install

Notice the --recursive option used with git. This is important because we 
need to download the yara subproject containing the source code for libyara 
(the core YARA library).


Lxml
^^^^

The lxml XML toolkit is a Pythonic binding for the C libraries libxml2 and libxslt. It is unique in that it 
combines the speed and XML feature completeness of these libraries with the simplicity of a native Python API, 
mostly compatible but superior to the well-known ElementTree API.

If not available as a package for your Linux distribution, the best way to install lxml is through pip.

.. code-block:: sh

        # pip install lxml


cChardet
^^^^^^^^

cChardet is high speed universal character encoding detector. cChardet homepage is located at
http://pypi.python.org/pypi/cchardet.

If not available as a package for your Linux distribution, the best way to install cChardet is through pip.

.. code-block:: sh

        # pip install cchardet


Requests
^^^^^^^^

Requests is an Apache2 Licensed HTTP library, written in Python, for human beings. Requests homepage is located 
at http://docs.python-requests.org/en/latest/

If not available as a package for your Linux distribution, the best way to install requests is through pip.

.. code-block:: sh

        # pip install requests


PySocks
^^^^^^^

PySocks is an actively maintained SocksiPy fork. It contains many improvements to the original. PySocks homepage 
is located at https://github.com/Anorov/PySocks.

If not available as a package for your Linux distribution, the best way to install requests is through pip.

.. code-block:: sh

        # pip install PySocks


Cssutils
^^^^^^^^

Cssutils is a CSS Cascading Style Sheets library for Python. Cssutils homepage is located at http://pypi.python.org/pypi/cssutils.

If not available as a package for your Linux distribution, the best way to install cssutils is through pip.


.. code-block:: sh

        # pip install cssutils


Zope Interface
^^^^^^^^^^^^^^

Zope Interface homepage is located at http://pypi.python.org/pypi/zope.interface.

If not available as a package for your Linux distribution, the best way to install zope.interface is 
through pip.

.. code-block:: sh

        # pip install zope.interface


Pygraphviz
^^^^^^^^^^

Pygraphviz homepage is located at http://pygraphviz.github.io.

If not available as a package for your Linux distribution, the best way to install pygraphviz is through 
pip.

.. code-block:: sh

        # pip install pygraphviz


Python-Magic
^^^^^^^^^^^^

The recommended implementation of python-magic can be found at https://github.com/ahupp/python-magic.

The best way to install python-magic is through pip.

.. code-block:: sh

        # pip install python-magic

If you are running Ubuntu, you may want to use a completely different implementation of python-magic 
which is packaged through apt.

.. code-block:: sh

        # apt-get install python-magic


Rarfile
^^^^^^^

Rarfile homepage is located at http://rarfile.berlios.de/.

If not available as a package for your Linux distribution, the best way to install rarfile is through pip.

.. code-block:: sh

        # pip install rarfile



NetworkX (optional)
^^^^^^^^^^^^^^^^^^^

NetworkX homepage is located at https://networkx.github.io/
 
NetworkX is a Python language software package for the creation, manipulation, and study of the structure, 
dynamics, and functions of complex networks.

If not available as a package for your Linux distribution, the best way to install networkx is through pip.

.. code-block:: sh

        # pip install networkx


PyMongo (optional)
^^^^^^^^^^^^^^^^^^

PyMongo homepage is located at http://www.mongodb.org/display/DOCS/Python+Language+Center.

If not available as a package for your Linux distribution, the best way to install pymongo is through pip.

.. code-block:: sh

        # pip install pymongo  


Python-Ssdeep (optional)
^^^^^^^^^^^^^^^^^^^^^^^^

Python-Ssdeep homepage is located at https://github.com/DinoTools/python-ssdeep.

If not available as a package for your Linux distribution, the best way to install python-ssdeep 
is through pip.

.. code-block:: sh

        # BUILD_LIB=1 pip install ssdeep
