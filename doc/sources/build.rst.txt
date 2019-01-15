.. _build:

Build and Install
=================

Requirements
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
