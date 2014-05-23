.. _configuration:

Configuration
==========================

.. toctree::
   :maxdepth: 2


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
