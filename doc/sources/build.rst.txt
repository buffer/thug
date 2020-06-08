.. _build:

Build and Install
=================

Requirements
------------

Python
^^^^^^

Python 3.6+ is required in order to properly run Thug. You may be lucky running it with
previous versions but please consider such versions are not supported. Please do not
report issues in such case. Python source code can be downloaded at http://www.python.org.


Boost
^^^^^

Boost provides free peer-reviewed portable C++ source libraries. Boost homepage is
located at http://www.boost.org/. 

Packages for most Linux distributions are available.


Google V8
^^^^^^^^^

V8 is Google’s open source high-performance JavaScript and WebAssembly engine, written
in C++. It is used in Chrome and in Node.js, among others. It implements ECMAScript and
WebAssembly, and runs on Windows 7 or later, macOS 10.12+, and Linux systems that use
x64, IA-32, ARM, or MIPS processors. V8 can run standalone, or can be embedded into any
C++ application.


**Python 3**

**Thug 0.10.6 is the last version supporting Python 2.7**. More recent versions support
just Python 3.6+. If you are installing a recent Thug version (and you should really
do that) you have to install STPyV8 (https://github.com/area1/stpyv8/).

STPyV8 is a Python/C++ wrapper that allows interoperability between Python 3 and
JavaScript running Google's V8 engine. STPyV8 is a fork of the original PyV8 project,
with code changed to work with the latest V8 engine and Python 3. STPyV8 links with
Google V8 built as a static library. Currently the library builds on Linux and MacOS,
with Windows planned for the future.

GCC/clang or equivalent and Python3 headers are needed to build the main STPyV8 source
code, as well as Boost-Python and some other Boost dependencies. For a short while,
Python 2.7 is still needed by Google's toolchain to build a local library version of V8.

A Python 3 virtual environment is recommended. (Google's build tools will establish their
own Python2 virtual environment during the compilation of V8, but this can be ignored).

Please look at https://github.com/area1/stpyv8/blob/master/docs/source/build.rst for
detailed building instructions. Moreover be aware that Python wheels are available for
the Linux platform at https://github.com/area1/stpyv8/releases for different versions
of Python.


**Python 2 (DEPRECATED)**

If you have some very good reasons to avoid moving to Python 3 be aware that Thug 0.10.6
is the last version supporting Python 2.7. In such case you have to install PyV8. Please
consider that PyV8 is not maintained so you could experience issues. Please do not report
related issues.

In order to properly install Google V8 and PyV8 please follow the procedure described 
below.

.. code-block:: sh

        $ git clone https://github.com/buffer/pyv8.git
        $ cd pyv8
        ~/pyv8 $ python setup.py build
        ~/pyv8 $ sudo python setup.py install


Graphviz
^^^^^^^^

Graphviz homepage is located at http://www.graphviz.org/.

Graphviz is open source graph visualization software. Graph visualization is a way of
representing structural information as diagrams of abstract graphs and networks. It
has important applications in networking, bioinformatics, software engineering, database
and web design, machine learning, and in visual interfaces for other technical domains.

Packages for most Linux distributions are available.


MongoDB (optional)
^^^^^^^^^^^^^^^^^^

MongoDB homepage is located at http://www.mongodb.org.

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

Alternatively you can clone the Thug repository and execute

.. code-block:: sh

    $ cd thug
    $ python setup.py build
    $ sudo python setup.py install


The procedure will install the dependencies not already mentioned in the previous sections so you 
should take care of installing them before actually installing Thug.
