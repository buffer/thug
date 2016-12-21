.. _intro:

Introduction
============

`Thug <https://github.com/buffer/thug>`_ is a Python low-interaction honeyclient based on an hybrid 
static/dynamic analysis approach.

Thug provides a DOM implementation which is (almost) compliant with W3C DOM Core, HTML, Events,
Views and Style specifications (Level 1, 2 and partially 3). [#f1]_

Thug makes use of the Google V8 Javascript engine [#f2]_ wrapped through PyV8 [#f3]_ in order to
analyze malicious Javascript code and of the Libemu library [#f4]_ wrapped through Pylibemu [#f5]_
in order to detect and emulate shellcodes.

Currently 9 Internet Explorer (Windows XP, Windows 2000, Windows 7, Windows 10), 21 Chrome (Windows 
XP, Windows 7, MacOS X, Android 4.0.3, Android 4.0.4, Android 4.1.2, Linux, iOS 7.1, iOS 7.1.1, iOS 
7.1.2, iOS 8.0.2, iOS 8.1.1, iOS 8.4.1, iOS 9.0.2), 4 Firefox (Windows XP, Windows 7, Linux) and 6 
Safari (Windows XP, Windows 7, MacOS X, iOS 7.0.4, iOS 8.0.2, iOS 9.1) personalities are emulated 
and about 90 vulnerability modules (ActiveX controls, core browser functionalities, browser plugins) 
are provided.


.. [#f1] `W3C DOM Specifications <http://www.w3.org/TR/#tr_DOM>`_

.. [#f2] `Google V8 <http://code.google.com/p/v8/>`_ is Google's open source JavaScript engine. V8 is written in C++ and is used in Google Chrome, the open source browser from Google.
         V8 implements ECMAScript as specified in ECMA-262, 3rd edition, and runs on Windows XP and Vista, Mac OS X 10.5 (Leopard), and Linux systems that use IA-32 or ARM processors.
         V8 can run standalone, or can be embedded into any C++ application.

.. [#f3] `PyV8 <http://code.google.com/p/pyv8/>`_ is a Python wrapper for the Google V8 engine. PyV8 acts as a bridge between the Python and JavaScript objects and supports the Google 
         V8 engine in Python scripts.

.. [#f4] `Libemu <http://libemu.carnivore.it/>`_ is a small library written in C offering basic x86 emulation and shellcode detection using GetPC heuristics. It is designed to be used 
         within network intrusion/prevention detections and honeypots.

.. [#f5] `Pylibemu <https://github.com/buffer/pylibemu>`_ is a Libemu Cython wrapper

