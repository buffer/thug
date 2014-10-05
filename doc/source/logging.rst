.. _logging:

Logging
*******

MongoDB Logging module
======================

MongoDB collection schema
-------------------------

Collection urls
^^^^^^^^^^^^^^^

The collection *urls* is used to keep track of the URLs visited during the analysis.
A URL is always associated a single entry in this collection even if it is visited 
multiple times (during the same analysis or in different analyses). Associating a 
unique ObjectID to a given URL allows to easily spot interesting scenarios like 
different redirection chains ending up using the same URLs. 

.. code-block:: sh

        { 
            "url" : URL
        }

Collection analyses
^^^^^^^^^^^^^^^^^^^

The collection *analyses* is used to keep track of the Thug analyses. The analysis
options used for the single analysis are stored together with other useful information 
like the used Thug version and the analysis datetime. Moreover the URL ObjectID of the 
initial URL is stored for convenience.

.. code-block:: sh


        { 
            "url"         : Initial URL url_id
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

Collection connections 
^^^^^^^^^^^^^^^^^^^^^^

The collection *connections* is used to keep track of the redirections which could happen
during the single analysis. The field *chain_id* is a counter which is incremented by one at 
every redirection and it's meant to be used in order to rebuild the redirection chain in the 
right order while analyzing data.

.. code-block:: sh

        { 
            "analysis_id"   : Analysis ID
            "chain_id"      : Chain ID 
            "source"        : Source URL url_id
            "destination"   : Destination URL url_id
            "method"        : Method
            "flags"         : Flags
        }


Collection locations 
^^^^^^^^^^^^^^^^^^^^

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

Collection samples
^^^^^^^^^^^^^^^^^^

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

Collection exploits
^^^^^^^^^^^^^^^^^^^

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


Collection codes
^^^^^^^^^^^^^^^^

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

Collection behaviors
^^^^^^^^^^^^^^^^^^^^

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

Collection graphs
^^^^^^^^^^^^^^^^^

The collection *graphs* is used to store the analysis JSON exploit graph.  

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "graph"         : JSON exploit graph
        }
