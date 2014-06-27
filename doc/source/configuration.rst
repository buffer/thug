.. _configuration:

Configuration
==========================

.. toctree::
   :maxdepth: 2


HoneyAgent (optional)
^^^^^^^^^^^^^^^^^^^^^

HoneyAgent is a Java agent library that creates a sandbox for Java 
applications and applets. It uses the JVMTI as well as the JNI to 
intercept class loading and function calls.

During runtime HoneyAgent traces function calls performed by the 
analyzed application. It shows which class calls which function 
with which parameters. Reflected function calls are translated to 
the original function names for simpler reading.

HoneyAgent provides simple means to hook individual Java functions 
e.g. to provide fake values to the analyzed application. These hooks 
are caller sensitive, so that default JRE classes can still function 
properly. The process of class loading is also intercepted to identify 
invalid bytecode and optionally make changes to get the class running 
within the observed environment.

To sandbox the application, file accesses are redirected to a jailed 
environment. Furthermore, Java properties as well as environment 
variables are faked due to according Java function hooks.

HoneyAgent source code can be downloaded at

https://bitbucket.org/fkie_cd_dare/honeyagent

It is HIGHLY suggested to run HoneyAgent in a dedicated VM because
there exists the possibility a sample could circumvent the sandbox
and compromise the machine. In such case please consider that a OVA
is available (and already configured) at

https://www.dropbox.com/s/6ky8uhhp121mlx9/Honeyagent.ova

Login   : thug 
Password: thug

In order to configure Thug to submit applets for analysis to HoneyAgent
rename the file src/honeyagent/honeyagent.conf.sample in src/honeyagent/honeyagent.conf
and edit it like shown later. 

.. code-block:: sh

    [HoneyAgent]
    scanurl:                        http://192.168.56.101:8000

Please note that if the file honeyagent.conf does not exists Thug will
assume you do not want to submit applets to HoneyAgent. Alternatively 
you can disable the HoneyAgent support through command line even if the
the honeyagent.conf file exists (option -N or --no-honeyagent).

This configuration instructs Thug to send the applet to analyze to the
server whose IP address is 192.168.56.101 (please verify your network 
configuration and modify it accordingly) listening on port 8000/tcp.

In order to enable this service run this commands on the HoneyAgent 
machine

.. code-block:: sh

    thug@honeyagent:~$ cd honeyagent/HoneyDaemon/
    thug@honeyagent:~/honeyagent/HoneyDaemon$ python daemon.py 8000 ../HoneyAppletViewer/analyze.sh ../HoneyAppletViewer/honeyagent.ini
    HoneyAgent daemon running on port 8000  


After the service is enabled and properly configured you should be
able to automatically analyze applets like shown later. 

.. code-block:: sh

    buffer@rigel ~/thug/src $ python thug.py http://10.3.6.54:8080/1
    [2014-06-27 15:08:11] [window open redirection] about:blank -> http://10.3.6.54:8080/1
    [2014-06-27 15:08:11] [HTTP Redirection (Status: 302)] Content-Location: http://10.3.6.54:8080/1 --> Location: http://10.3.6.54:8080/1/
    [2014-06-27 15:08:11] [HTTP] URL: http://10.3.6.54:8080/1/ (Status: 200, Referrer: None)
    [2014-06-27 15:08:11] [HTTP] URL: http://10.3.6.54:8080/1/ (Content-type: text/html, MD5: 48c4de9dbd60eb2b7142045b70c5193d)
    [2014-06-27 15:08:11] <applet archive="hOVwjoAj.jar" code="KqeR.class" height="1" width="1"></applet>
    [2014-06-27 15:08:11] [Navigator URL Translation] hOVwjoAj.jar --> http://10.3.6.54:8080/1/hOVwjoAj.jar
    [2014-06-27 15:08:11] [applet redirection] http://10.3.6.54:8080/1/ -> http://10.3.6.54:8080/1/hOVwjoAj.jar
    [2014-06-27 15:08:11] [HTTP] URL: http://10.3.6.54:8080/1/hOVwjoAj.jar (Status: 200, Referrer: http://10.3.6.54:8080/1/)
    [2014-06-27 15:08:11] [HTTP] URL: http://10.3.6.54:8080/1/hOVwjoAj.jar (Content-type: application/octet-stream, MD5: 42f928fbf0d7f0a10a61576f2cf5919d)
    [2014-06-27 15:08:15] [HoneyAgent] Sample 42f928fbf0d7f0a10a61576f2cf5919d submitted
    [2014-06-27 15:08:15] [HoneyAgent] Sample 42f928fbf0d7f0a10a61576f2cf5919d dropped sample rbbxVSJWaL.dat
    [2014-06-27 15:08:15] [HoneyAgent] Sample 42f928fbf0d7f0a10a61576f2cf5919d dropped sample DyXgXpD.class
    [2014-06-27 15:08:19] [HoneyAgent] Sample 42f928fbf0d7f0a10a61576f2cf5919d dropped sample RcFBBkMa.exe
    [2014-06-27 15:08:19] Saving log analysis at ../logs/c2b78e6e949138622263f77d4ec946fd/20140627150811
    
    buffer@rigel ~/thug/src $ cd ../logs/c2b78e6e949138622263f77d4ec946fd/20140627150811/analysis/honeyagent/
    buffer@rigel ~/thug/logs/c2b78e6e949138622263f77d4ec946fd/20140627150811/analysis/honeyagent $ ls -lhR
    .:                              
    total 680K                      
    -rw-r--r-- 1 buffer buffer 679K Jun 27 15:08 42f928fbf0d7f0a10a61576f2cf5919d
    drwxr-xr-x 2 buffer buffer   66 Jun 27 15:08 dropped
                                    
    ./dropped:
    total 92K
    -rw-r--r-- 1 buffer buffer 9.2K Jun 27 15:08 DyXgXpD.class
    -rw-r--r-- 1 buffer buffer  73K Jun 27 15:08 RcFBBkMa.exe
    -rw-r--r-- 1 buffer buffer  109 Jun 27 15:08 rbbxVSJWaL.dat

    buffer@rigel ~/thug/logs/c2b78e6e949138622263f77d4ec946fd/20140627150811/analysis/honeyagent/dropped $ file *
    DyXgXpD.class:  compiled Java class data, version 45.3
    RcFBBkMa.exe:   PE32 executable (GUI) Intel 80386, for MS Windows
    rbbxVSJWaL.dat: ASCII text


VirusTotal (optional)
^^^^^^^^^^^^^^^^^^^^^

VirusTotal is a free service that analyzes suspicious files and URLs and 
facilitates the quick detection of viruses, worms, trojans, and all kinds 
of malware. 

Thug supports VirusTotal but you need to get an API key to use the 
VirusTotal Public API 2.0. To do so, just sign-up on the service at 
https://www.virustotal.com/ and get your own API Key.

Rename the file src/Logging/virustotal.conf.sample in src/Logging/virustotal.conf
and insert your own API key in the configuration file as shown below

.. code-block:: sh

    [VirusTotal]
    apikey:                         <enter your API key here>
    scanurl:                        https://www.virustotal.com/vtapi/v2/file/scan
    reporturl:                      https://www.virustotal.com/vtapi/v2/file/report
