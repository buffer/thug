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

https://www.dropbox.com/s/qieyfe97qvh7pjp/Honeyagent-r2.ova

Login   : thug 
Password: thug

In order to configure Thug to submit applets for analysis to HoneyAgent
edit the configuration file */etc/thug/thug.conf* as shown later.

.. code-block:: sh

    [honeyagent]
    scanurl:                        http://192.168.56.101:8000

Please note that if the file *thug.conf* does not exists Thug will
assume you do not want to submit applets to HoneyAgent. Alternatively 
you can disable the HoneyAgent support through command line even if the
the *thug.conf* file exists (option -N or --no-honeyagent).

This configuration instructs Thug to send the applet to analyze to the
server whose IP address is 192.168.56.101 (please verify your network 
configuration and modify it accordingly) listening on port 8000/tcp.

In order to enable this service run this commands on the HoneyAgent 
machine

.. code-block:: sh

    thug@honeyagent:~$ cd honeyagent/HoneyDaemon/
    thug@honeyagent:~/honeyagent/HoneyDaemon$ python daemon.py run.ini
    HoneyAgent daemon running on port 8000  


After the service is enabled and properly configured you should be
able to automatically analyze applets like shown later. 

.. code-block:: sh

    buffer@rigel ~ $ thug http://192.168.0.100:8080/1
    [2014-07-07 23:50:53] [window open redirection] about:blank -> http://192.168.0.100:8080/1
    [2014-07-07 23:50:53] [HTTP Redirection (Status: 302)] Content-Location: http://192.168.0.100:8080/1 --> Location: http://192.168.0.100:8080/1/
    [2014-07-07 23:50:53] [HTTP] URL: http://192.168.0.100:8080/1/ (Status: 200, Referrer: None)
    [2014-07-07 23:50:53] [HTTP] URL: http://192.168.0.100:8080/1/ (Content-type: text/html, MD5: 514658fc397a7f227bd0d3e11b22c428)
    [2014-07-07 23:50:53] <applet archive="qqNqSoke.jar" code="BTrJ.class" height="1" width="1"></applet>
    [2014-07-07 23:50:53] [Navigator URL Translation] qqNqSoke.jar --> http://192.168.0.100:8080/1/qqNqSoke.jar
    [2014-07-07 23:50:53] [applet redirection] http://192.168.0.100:8080/1/ -> http://192.168.0.100:8080/1/qqNqSoke.jar
    [2014-07-07 23:50:53] [HTTP] URL: http://192.168.0.100:8080/1/qqNqSoke.jar (Status: 200, Referrer: http://192.168.0.100:8080/1/)
    [2014-07-07 23:50:53] [HTTP] URL: http://192.168.0.100:8080/1/qqNqSoke.jar (Content-type: application/octet-stream, MD5: 1b3354f594522ff32791c278f50f2efa)
    [2014-07-07 23:50:56] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Sample submitted
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Dropped sample uAzpYJRZ.exe
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Dropped sample IixfXAb.class
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Dropped sample ArIBNUkvAi.dat
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Yara heuristics rule CreatesNewProcess match
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Yara heuristics rule WritesMZFile match
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Yara heuristics rule WritesExeFile match
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Yara heuristics rule LocalFileAccess match
    [2014-07-07 23:50:57] [HoneyAgent][1b3354f594522ff32791c278f50f2efa] Yara heuristics rule RestrictedPropertyAccess match
    [2014-07-07 23:50:57] Saving log analysis at /tmp/thug/logs/97ae3a4c476f3efab64b70b26b0f7b57/20140707235053
    
    buffer@rigel ~ $ cd /tmp/thug/logs/97ae3a4c476f3efab64b70b26b0f7b57/20140707235053/analysis/honeyagent/
    buffer@rigel /tmp/thug/logs/97ae3a4c476f3efab64b70b26b0f7b57/20140707235053/analysis/honeyagent $ ls -lhR
    .:
    total 668K
    -rw-r--r-- 1 buffer buffer 665K Jul  7 23:50 1b3354f594522ff32791c278f50f2efa.json
    drwxr-xr-x 2 buffer buffer   66 Jul  7 23:50 dropped
    
    ./dropped:
    total 92K
    -rw-r--r-- 1 buffer buffer  110 Jul  7 23:50 ArIBNUkvAi.dat
    -rw-r--r-- 1 buffer buffer 9.2K Jul  7 23:50 IixfXAb.class
    -rw-r--r-- 1 buffer buffer  73K Jul  7 23:50 uAzpYJRZ.exe
    
    buffer@rigel /tmp/thug/logs/97ae3a4c476f3efab64b70b26b0f7b57/20140707235053/analysis/honeyagent $ cd dropped/
    buffer@rigel /tmp/thug/logs/97ae3a4c476f3efab64b70b26b0f7b57/20140707235053/analysis/honeyagent/dropped $ file *
    ArIBNUkvAi.dat: ASCII text
    IixfXAb.class:  compiled Java class data, version 45.3
    uAzpYJRZ.exe:   PE32 executable (GUI) Intel 80386, for MS Windows


VirusTotal (optional)
^^^^^^^^^^^^^^^^^^^^^

VirusTotal is a free service that analyzes suspicious files and URLs and 
facilitates the quick detection of viruses, worms, trojans, and all kinds 
of malware. 

Thug supports VirusTotal and a default API key is now included in the default
configuration file (many thanks to the VirusTotal team). To change the default 
VirusTotal key with your own, simply edit */etc/thug/thug.conf* as shown
later.

.. code-block:: sh

    [virustotal]
    apikey:                         <enter your API key here>
    scanurl:                        https://www.virustotal.com/vtapi/v2/file/scan
    reporturl:                      https://www.virustotal.com/vtapi/v2/file/report

You may also pass a runtime value for the API key parameter by using the --vt-apikey or -b parameter:
this may come handy when using a dockerized Thug instance where editing the configuration file prior
to each run may not be that simple.
