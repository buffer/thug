.. Thug documentation master file, created by
   sphinx-quickstart on Wed Jun 13 00:07:06 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Thug's documentation!
================================

`Thug <https://github.com/buffer/thug>`_ is a Python low-interaction honeyclient based on an hybrid 
static/dynamic analysis approach.

Thug provides a DOM implementation which is (almost) compliant with W3C DOM Core, HTML, Events and 
Views specifications (Level 1, 2 and partially 3) and partially compliant with W3C DOM Style 
specifications. [#f1]_

Thug makes use of the Google V8 Javascript engine [#f2]_ wrapped through PyV8 [#f3]_ in order to 
analyze malicious Javascript code and of the Libemu library [#f4]_ wrapped through Pylibemu [#f5]_
in order to detect and emulate shellcodes. 

Currently 6 Internet Explorer personalities are emulated and about 90 vulnerability modules (ActiveX 
controls, core browser functionalities, browser plugins) are provided. 

.. toctree::
   :maxdepth: 2

   intro
   build
   usage

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. rubric:: Footnotes

.. [#f1] `W3C DOM Specifications <http://www.w3.org/TR/#tr_DOM>`_

.. [#f2] `Google V8 <http://code.google.com/p/v8/>`_ is Google's open source JavaScript engine. V8 is written in C++ and is used in Google Chrome, the open source browser from Google.
         V8 implements ECMAScript as specified in ECMA-262, 3rd edition, and runs on Windows XP and Vista, Mac OS X 10.5 (Leopard), and Linux systems that use IA-32 or ARM processors.
         V8 can run standalone, or can be embedded into any C++ application.

.. [#f3] `PyV8 <http://code.google.com/p/pyv8/>`_ is a Python wrapper for the Google V8 engine. PyV8 acts as a bridge between the Python and JavaScript objects and supports the Google 
         V8 engine in Python scripts.

.. [#f4] `Libemu <http://libemu.carnivore.it/>`_ is a small library written in C offering basic x86 emulation and shellcode detection using GetPC heuristics. It is designed to be used 
         within network intrusion/prevention detections and honeypots.

.. [#f5] `Pylibemu <https://github.com/buffer/pylibemu>`_ is a Libemu Cython wrapper
