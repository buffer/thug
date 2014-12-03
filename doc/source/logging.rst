.. _logging:

Logging
*******

Currently different logging modes are available in Thug. Some of them can be combined
in order to store the result of the analysis in different formats if needed. By default
Thug attempts storing analysis logs in a MongoDB instance (see later for a detailed
explanation of the MongoDB collection schema).

*BEWARE*: if a MongoDB instance is not available and no other logging mode is selected
Thug will not store any analysis log.

The available logging modes are:

* MongoDB logging mode (enabled by default)
* JSON logging mode
* MAEC 1.1 logging mode
* File logging mode


Logging configuration
=====================

The configuration file *Logging/logging.conf* defines the way Thug uses to log the results 
of its analyses. The default logging.conf file is shown below. 

.. code-block:: sh

    [modules]
    maec11:     Logging.modules.MITRE.MAEC11
    json:       Logging.modules.JSON
    mongodb:    Logging.modules.MongoDB
    hpfeeds:    Logging.modules.HPFeeds

    [hpfeeds]
    enable:     True
    host:       hpfeeds.honeycloud.net
    port:       10000
    ident:      q6jyo@hp1
    secret:     edymvouqpfe1ivud

    [mongodb]
    enable:     True
    host:       localhost
    port:       27017

The different sections of the configuration files will be explained later in this 
document. Just a suggestion before diving into details. *DO NOT CHANGE* the *modules*
section unless you know exactly what you are doing.


MongoDB logging mode
====================

By default Thug attempts storing the result of its analyses in a MongoDB instance.
The configuration file Logging/logging.conf defines the MongoDB instance configuration
parameters

.. code-block:: sh

    [mongodb]
    enable:     True
    host:       localhost
    port:       27017

The parameters should be quite intuitive to understand. By the way if you install 
MongoDB on the same host you are supposed to run Thug you should not need changing
anything in the default configuration.


Collection schema
-----------------

urls
^^^^

The collection *urls* is used to keep track of the URLs visited during the analysis.
A URL is always associated a single entry in this collection even if it is visited 
multiple times (during the same analysis or in different analyses). Associating a 
unique ObjectID to a given URL allows to easily spot interesting scenarios like 
different redirection chains ending up using the same URLs. 

.. code-block:: sh

        { 
            "url" : URL
        }

analyses
^^^^^^^^

The collection *analyses* is used to keep track of the Thug analyses. The analysis
options used for the single analysis are stored together with other useful information 
like the used Thug version and the analysis datetime. Moreover the URL ObjectID of the 
initial URL is stored for convenience.

.. code-block:: sh


        { 
            "url_id"      : Initial URL url_id
            "timestamp"   : Analysis datetime
            "thug"        : {
                                "version"            : Thug version
                                "personality" : { 
                                    "useragent"      : User Agent
                                },
                                "plugins" : { 
                                    "acropdf"        : Acrobat Reader version (if any)
                                    "javaplugin"     : JavaPlugin version (if any)
                                    "shockwaveflash" : Shockwave Flash version (if any)
                                },
                                "options" : { 
                                    "local"          : Local analysis
                                    "nofetch"        : Local no-fetch analysis
                                    "proxy"          : Proxy (if any)
                                    "events"         : Additional DOM events to be processed
                                    "delay"          : Maximum setTimeout/setInterval delay value (in milliseconds)
                                    "referer"        : Referer
                                    "timeout"        : Analysis timeout
                                    "threshold"      : Maximum pages to fetch
                                    "extensive"      : Extensive fetch of linked pages
                                },
                            }
        }

connections
^^^^^^^^^^^

The collection *connections* is used to keep track of the redirections which could happen
during the single analysis. The field *chain_id* is a counter which is incremented by one at 
every redirection and it's meant to be used in order to rebuild the redirection chain in the 
right order while analyzing data.

.. code-block:: sh

        { 
            "analysis_id"    : Analysis ID
            "chain_id"       : Chain ID
            "source_id"      : Source URL url_id
            "destination_id" : Destination URL url_id
            "method"         : Method
            "flags"          : Flags
        }

locations
^^^^^^^^^

The collection *locations* is used to keep track of the content stored at each URL visited
during the analysis. The content is stored in a MongoDB GridFS and additional metadata are 
saved like MD5 and SHA-256 checksums, content size, content type (as served by the server)
and evaluated content type.

.. code-block:: sh


        { 
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "content_id"    : Content ID (content stored in the GridFS fs)
            "content-type"  : Content Type
            "md5"           : MD5 checksum
            "sha256"        : SHA-256 checksum
            "flags"         : Flags
            "size"          : Data size
            "mime-type"     : Evaluated content type
        }

samples
^^^^^^^

The collection *samples* is used to keep track of the downloaded samples (currently supported 
types: PE, PDF, JAR and SWF). The sample itself is stored in a MongoDB GridFS and additional 
metadata are saved like MD5 and SHA-1 checksums, sample type and imphash (if the sample type 
is PE).

.. code-block:: sh

        { 
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "sample_id"     : Sample ID (sample stored in the GridFS fs)
            "type"          : Sample type
            "md5"           : MD5 checksum
            "sha1"          : SHA-1 checksum
            "imphash"       : Imphash (if type is PE)
        }

exploits
^^^^^^^^

The collection *eploits* is used to keep track of the exploits which were successfully 
identified during the analysis while visiting the URL referenced by *url_id*.

.. code-block:: sh

        {
            'analysis_id' : Analysis ID
            'url_id'      : URL url_id
            'module'      : Module/ActiveX Control, etc. that gets exploited
            'description' : Description of the exploit
            'cve'         : CVE number (if available)
            'data'        : Additional information
        }

codes
^^^^^

The collection *codes* is used to keep track of the (dynamic language) snippets of code 
identified during the analysis.

.. code-block:: sh

        {
            'analysis_id'  : Analysis ID
            'snippet'      : Code snippet
            'language'     : Code language
            'relationship' : Relationship with the page that references the code
            'method'       : Analysis method
        }

behaviors
^^^^^^^^^

The collection *behaviors* is used to keep track of the suspicious and/or malicious 
behaviors observed during the analysis.

.. code-block:: sh

        {
            'analysis_id' : Analysis ID
            'description' : Observed behavior description 
            'cve'         : CVE number (if available)
            'method'      : Analysis method
            'timestamp'   : Timestamp
        }

certificates
^^^^^^^^^^^^

The collection *certificates* is used to store the SSL certificates collected from
servers during the analysis.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "certificate"   : SSL certificate
        }

graphs
^^^^^^

The collection *graphs* is used to store the analysis JSON exploit graph.  

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "graph"         : JSON exploit graph
        }

virustotal
^^^^^^^^^^

The collection *virustotal* is used to store the VirusTotal sample analysis reports.
The Sample ObjectID references the *samples* collection.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "sample_id"     : Sample ID
            "report"        : VirusTotal report (JSON)
        }

honeyagent
^^^^^^^^^^

The collection *honeyagent* is used to store the HoneyAgent Java sandbox sample analysis
reports. The Sample ObjectID references the *samples* collection.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "sample_id"     : Sample ID
            "report"        : HoneyAgent report (JSON)
        }

androguard
^^^^^^^^^^

The collection *androguard* is used to store the Androguard APK sample analysis reports. 
The Sample ObjectID references the *samples* collection.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "sample_id"     : Sample ID
            "report"        : Androguard report (TXT)
        }

peepdf
^^^^^^

The collection *peepdf* is used to store the PeePDF PDF sample analysis reports.
The Sample ObjectID references the *samples* collection.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "sample_id"     : Sample ID
            "report"        : PeePDF report (XML)
        }

maec11
^^^^^^

The collection *maec11* is used to store the Thug analysis reports in MITRE MAEC 1.1
format. MAEC 1.1 logging mode should be enabled in order to have Thug saving data in
this collection

.. code-block:: sh

    {
            "analysis_id"   : Analysis ID
            "report"        : Analysis report (MITRE MAEC 1.1 format - XML)
    }

json
^^^^

The collection *json* is used to store the Thug analysis reports in JSON format. 
JSON logging mode should be enabled in order to have Thug saving data in
this collection

.. code-block:: sh

    {
            "analysis_id"   : Analysis ID
            "report"        : Analysis report (JSON)
    }

JSON logging mode
=================


MAEC 1.1 logging mode
=====================


File logging mode
=================


