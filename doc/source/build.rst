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
* Libemu                   
* Pylibemu                 
* Pefile                   
* Chardet                  
* httplib2 
* Zope interface           
* MongoDB (optional)       
* PyMongo (optional)       


Installation
------------


Python
^^^^^^

Python 2.7 is required in order to properly run Thug. You may be lucky running it with
Python 2.6 but please consider that it is not supported so issues related to Python 2.6
will be simply ignored. Python source code can be downloaded at http://www.python.org.


Google V8/PyV8
^^^^^^^^^^^^^^
  
Google V8 is Google’s open source JavaScript engine. V8 is written in C++ and is used 
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

2. Patch V8 source code with the patches you can find in thug/patches
   directory

.. code-block:: sh

        $ cp thug/patches/V8-patch* .
        $ patch -p0 < V8-patch1.diff 
        patching file v8/src/log.h
        $ patch -p0 < V8-patch2.diff 
        patching file v8/src/parser.h
        Hunk #1 succeeded at 456 (offset 7 lines).

3. Checkout PyV8 source code from SVN

.. code-block:: sh

        $ svn checkout http://pyv8.googlecode.com/svn/trunk/ pyv8

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

7. Test the installation

.. code-block:: sh

        ~/pyv8 $ python PyV8.py

   If no problems occur, you have successfully installed V8 and PyV8.


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


Zope Interface
^^^^^^^^^^^^^^

Zope Interface homepage is located at http://pypi.python.org/pypi/zope.interface.

If not available as a package for your Linux distribution, the best way
to install zope.interface is through easy_install.

.. code-block:: sh

        # easy_install zope.interface

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

