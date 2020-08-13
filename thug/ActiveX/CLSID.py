#!/usr/bin/env python
#
# CLSID.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

from .modules import AcroPDF
from .modules import AdodbRecordset
from .modules import AdodbStream
from .modules import AnswerWorks
from .modules import AolAmpX
from .modules import AolICQ
from .modules import AOLAttack
from .modules import BaiduBar
from .modules import BitDefender
from .modules import CABrightStor
from .modules import CGAgent
from .modules import Comodo
from .modules import ConnectAndEnterRoom
from .modules import CreativeSoftAttack
from .modules import DirectShow
from .modules import DivX
from .modules import DLinkMPEG
from .modules import Domino
from .modules import DPClient
from .modules import DVRHOSTWeb
from .modules import EnjoySAP
from .modules import FacebookPhotoUploader
from .modules import FileUploader
from .modules import GatewayWeblaunch
from .modules import GLIEDown2
from .modules import Gogago
from .modules import GomWeb
from .modules import HPInfo
from .modules import ICQToolbar
from .modules import IMWebControl
from .modules import InternetCleverSuite
from .modules import JavaDeploymentToolkit
from .modules import JetAudioDownloadFromMusicStore
from .modules import Kingsoft
from .modules import MacrovisionFlexNet
from .modules import MicrosoftWorks7Attack
from .modules import MicrosoftXMLDOM
from .modules import MicrosoftXMLHTTP
from .modules import Move
from .modules import MSRICHTXT
from .modules import MSVFP
from .modules import MSXML2DOMDocument
from .modules import MyspaceUploader
from .modules import NamoInstaller
from .modules import NCTAudioFile2
from .modules import NeoTracePro
from .modules import NessusScanCtrl
from .modules import OfficeOCX
from .modules import OurgameGLWorld
from .modules import PPlayer
from .modules import PTZCamPanel
from .modules import QuantumStreaming
from .modules import QvodCtrl
from .modules import RDSDataSpace
from .modules import RealPlayer
from .modules import RediffBolDownloaderAttack
from .modules import RegistryPro
from .modules import RisingScanner
from .modules import RtspVaPgCtrl
from .modules import ScriptingEncoder
from .modules import ScriptingFileSystemObject
from .modules import ShellApplication
from .modules import Shockwave
from .modules import ShockwaveFlash9
from .modules import ShockwaveFlash10
from .modules import ShockwaveFlash11
from .modules import ShockwaveFlash12
from .modules import SilverLight
from .modules import SinaDLoader
from .modules import SnapshotViewer
from .modules import SonicWallNetExtenderAddRouteEntry
from .modules import Spreadsheet
from .modules import SSReaderPdg2
from .modules import StormConfig
from .modules import StormMps
from .modules import SymantecAppStream
from .modules import SymantecBackupExec
from .modules import StreamAudioChainCast
from .modules import Toshiba
from .modules import UniversalUpload
from .modules import UUSeeUpdate
from .modules import VisualStudioDTE80
from .modules import VLC
from .modules import VsaIDEDTE
from .modules import VsmIDEDTE
from .modules import WebViewFolderIcon
from .modules import WindowsMediaPlayer
from .modules import WinNTSystemInfo
from .modules import WinZip
from .modules import WMEncProfileManager
from .modules import WMP
from .modules import WScriptShell
from .modules import WScriptShortcut
from .modules import WScriptNetwork
from .modules import XMLDOMParseError
from .modules import XUpload
from .modules import YahooJukebox
from .modules import YahooMessengerCyft
from .modules import YahooMessengerYVerInfo
from .modules import YahooMessengerYwcvwr
from .modules import ZenturiProgramCheckerAttack


CLSID = [
        # AcroPDF.PDF
        {
            'id'        : ( 'CA8A9780-280D-11CF-A24D-444553540000', ),
            'name'      : ( 'acropdf.pdf', 'pdf.pdfctrl', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetVersions'   : AcroPDF.GetVersions,
                            'GetVariable'   : AcroPDF.GetVariable,
                          }
        },

        # AcubeFileCtrl
        {
            'id'        : (),
            'name'      : ( 'acubefilectrl.acubefilectrlctrl.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {},
        },

        # Adodb.Recordset
        {
            'id'        : (),
            'name'      : ( 'adodb.recordset', ),
            'attrs'     : {
                            'Fields'        : AdodbRecordset.Fields(),
                          },
            'funcattrs' : {},
            'methods'   : {}
        },

        # Adodb.Stream
        {
            'id'        : (),
            'name'      : ( 'adodb.stream', ),
            'attrs'     : {
                            'Charset'       : 'Unicode',
                            'type'          : 1,
                            'Type'          : 1,
                            'Mode'          : 3,
                            'Position'      : 0,
                            'position'      : 0,
                            '_files'        : dict(),
                            '_current'      : None,
                          },
            'funcattrs' : {
                            'position'      : AdodbStream.setPosition,
                            'Size'          : AdodbStream.getSize
                          },
            'methods'   : {
                            'Open'          : AdodbStream.open,
                            'Read'          : AdodbStream.Read,
                            'Write'         : AdodbStream.Write,
                            'SaveToFile'    : AdodbStream.SaveToFile,
                            'SaveTofile'    : AdodbStream.SaveToFile,
                            'LoadFromFile'  : AdodbStream.LoadFromFile,
                            'ReadText'      : AdodbStream.ReadText,
                            'WriteText'     : AdodbStream.WriteText,
                            'Close'         : AdodbStream.Close,
                            'setPosition'   : AdodbStream.setPosition,
                            'getSize'       : AdodbStream.getSize,
                         }
        },

        # AnswerWorks
        {
            'id'        : ( 'C1908682-7B2C-4AB0-B98E-183649A0BF84', ),
            'name'      : ( 'awapi4.answerworks.1'),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetHistory'    : AnswerWorks.GetHistory,
                            'GetSeedQuery'  : AnswerWorks.GetSeedQuery,
                            'SetSeedQuery'  : AnswerWorks.SetSeedQuery,
                          }
        },

        # AolAmpX
        {
            'id'        : ( 'B49C4597-8721-4789-9250-315DFBD9F525',
                            'FA3662C3-B8E8-11D6-A667-0010B556D978',
                            'FE0BD779-44EE-4A4B-AA2E-743C63F2E5E6' ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'AppendFileToPlayList'  : AolAmpX.AppendFileToPlayList,
                            'ConvertFile'           : AolAmpX.ConvertFile,
                          }
        },

        # AolICQ
        {
            'id'        : (),
            'name'      : ( 'icqphone.sipxphonemanager.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DownloadAgent'         : AolICQ.DownloadAgent,
                          }
        },

        # AOLAttack
        {
            'id'        : ( '189504B8-50D1-4AA8-B4D6-95C8F58A6414', ),
            'name'      : ( 'sb.superbuddy', 'sb.superbuddy.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'LinkSBIcons'           : AOLAttack.LinkSBIcons,
                          }
        },

        # BaiduBar
        {
            'id'        : ( 'A7F05EE4-0426-454F-8013-C41E3596E9E9', ),
            'name'      : ( 'baidubar.tool', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DloadDS'               : BaiduBar.DloadDS,
                          }
        },

        # BitDefender
        {
            'id'        : ( '5D86DDB5-BDF9-441B-9E9E-D4730F4EE499', ),
            'name'      : ( ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'initx'                 : BitDefender.initx,
                          }
        },

        # CABrightStor
        {
            'id'        : ( 'BF6EFFF3-4558-4C4C-ADAF-A87891C5F3A3', ),
            'name'      : ( 'listctrl.listctrlctrl.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'AddColumn'              : CABrightStor.AddColumn,
                          }
        },

        # CGAgent
        {
            'id'        : ( '75108B29-202F-493C-86C5-1C182A485C4C', ),
            'name'      : ( 'cgagent.agent.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'CreateChinagames'       : CGAgent.CreateChinagames,
                          }
        },

        # Comodo
        {
            'id'        : ( '309F674D-E4D3-46BD-B9E2-ED7DFD7FD176', ),
            'name'      : ( ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'ExecuteStr'             : Comodo.ExecuteStr,
                          }
        },

        # ConnectAndEnterRoom
        {
            'id'        : ( 'AE93C5DF-A990-11D1-AEBD-5254ABDD2B69', ),
            'name'      : ( 'glchat.glchatctrl.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'ConnectAndEnterRoom'    : ConnectAndEnterRoom.ConnectAndEnterRoom,
                          }
        },

        # CreativeSoftAttack
        {
            'id'        : ( '0A5FD7C5-A45C-49FC-ADB5-9952547D5715', ),
            'name'      : (),
            'attrs'     : {
                            'cachefolder'           : '',
                          },
            'funcattrs' : {
                            'cachefolder'           : CreativeSoftAttack.Setcachefolder,
                          },
            'methods'   : {
                            'Setcachefolder'        : CreativeSoftAttack.Setcachefolder,
                          }
        },

        # DirectShow
        {
            'id'        : ( '0955AC62-BF2E-4CBA-A2B9-A63F772D46CF', ),
            'name'      : (),
            'attrs'     : {
                            'data'                  : '',
                            'width'                 : '1',
                            'height'                : '1',
                          },
            'funcattrs' : {
                            'data'                  : DirectShow.Setdata,
                          },
            'methods'   : {
                            'Setdata'               : DirectShow.Setdata,
                          }
        },

        # DivX
        {
            'id'        : ( 'D050D736-2D21-4723-AD58-5B541FFB6C11', ),
            'name'      : (),
            'attrs'     : {
                            'onload'                : None,
                            'onmousemove'           : None,
                            'onclick'               : None
                          },
            'funcattrs' : {},
            'methods'   : {
                            'SetPassword'           : DivX.SetPassword,
                          }
        },

        # DLinkMPEG
        {
            'id'        : ( 'A93B47FD-9BF6-4DA8-97FC-9270B9D64A6C', ),
            'name'      : (),
            'attrs'     : {
                            'Url'                   : ''
                          },
            'funcattrs' : {
                            'Url'                   : DLinkMPEG.SetUrl,
                          },
            'methods'   : {
                            'SetUrl'                : DLinkMPEG.SetUrl,
                          }
        },

        # Domino
        {
            'id'        : ( 'E008A543-CEFB-4559-912F-C27C2B89F13B',
                            '3BFFE033-BF43-11D5-A271-00A024A51325',
                            '983A9C21-8207-4B58-BBB8-0EBC3D7C5505',
                          ),
            'name'      : (),
            'attrs'     : {
                            'General_ServerName'        : '',
                            'General_JunctionName'      : '',
                            'Mail_MailDbPath'           : '',
                          },
            'funcattrs' : {
                            'General_ServerName'        : Domino.SetGeneral_ServerName,
                            'General_JunctionName'      : Domino.SetGeneral_JunctionName,
                            'Mail_MailDbPath'           : Domino.SetMail_MailDbPath
                          },
            'methods'   : {
                            'SetGeneral_ServerName'     : Domino.SetGeneral_ServerName,
                            'SetGeneral_JunctionName'   : Domino.SetGeneral_JunctionName,
                            'SetMail_MailDbPath'        : Domino.SetMail_MailDbPath,
                            'InstallBrowserHelperDll'   : Domino.InstallBrowserHelperDll,
                          }
        },

        # DPClient
        {
            'id'        : ( 'EEDD6FF9-13DE-496B-9A1C-D78B3215E266', ),
            'name'      : ( 'dpclient.vod.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DownURL2'          : DPClient.DownURL2,
                          }
        },

        # DuZoneRPSSO
        {
            'id'        : (),
            'name'      : ( 'duzonerpsso.duzonerpssoctrl.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {},
        },

        # DVRHOSTWeb
        {
            'id'        : ( 'D64CF6D4-45DF-4D8F-9F14-E65FADF2777C', ),
            'name'      : ( 'pdvratl.pdvrocx.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'TimeSpanFormat'    : DVRHOSTWeb.TimeSpanFormat,
                          }
        },

        # EasyPayPlugin
        {
            'id'        : (),
            'name'      : ( 'easypayplugin.epplugin.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {},
        },

        # EnjoySAP
        {
            'id'        : ( '2137278D-EF5C-11D3-96CE-0004AC965257', ),
            'name'      : ( 'rfcguisink.rfcguisink.1', 'kweditcontrol.kwedit.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'LaunchGui'         : EnjoySAP.LaunchGui,
                            'PrepareToPostHTML' : EnjoySAP.PrepareToPostHTML,
                            'Comp_Download'     : EnjoySAP.Comp_Download
                          }
        },

        # FacebookPhotoUploader
        {
            'id'        : ( '6E5E167B-1566-4316-B27F-0DDAB3484CF7',
                            '5C6698D9-7BE4-4122-8EC5-291D84DBD4A0',
                            'BA162249-F2C5-4851-8ADC-FC58CB424243', ),
            'name'      : ( 'thefacebook.facebookphotouploader4.4.1', ),
            'attrs'     : {
                            'ExtractIptc'       : '',
                            'ExtractExif'       : '',
                          },
            'funcattrs' : {
                            'ExtractIptc'       : FacebookPhotoUploader.SetExtractIptc,
                            'ExtractExif'       : FacebookPhotoUploader.SetExtractExif,
                          },
            'methods'   : {
                            'SetExtractIptc'    : FacebookPhotoUploader.SetExtractIptc,
                            'SetExtractExif'    : FacebookPhotoUploader.SetExtractExif,
                          }
        },

        # FileUploader
        {
            'id'        : ( 'C36112BF-2FA3-4694-8603-3B510EA3B465', ),
            'name'      : ( 'fileuploader.fuploadctl.1', ),
            'attrs'     : {
                            'HandwriterFilename'    : ''
                          },
            'funcattrs' : {
                            'HandwriterFilename'    :  FileUploader.SetHandwriterFilename,
                          },
            'methods'   : {
                            'SetHandwriterFilename' :  FileUploader.SetHandwriterFilename,
                          }
        },

        # Flash
        {
            'id'        : ( 'D27CDB6E-AE6D-11CF-96B8-444553540000', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {},
        },

        # GatewayWeblaunch
        {
            'id'        : ( '93CEA8A4-6059-4E0B-ADDD-73848153DD5E',
                            '97BB6657-DC7F-4489-9067-51FAB9D8857E'),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DoWebLaunch'           : GatewayWeblaunch.DoWebLaunch,
                          }
        },

        # GLIEDown2
        {
            'id'        : ( 'F917534D-535B-416B-8E8F-0C04756C31A8', ),
            'name'      : ( 'gliedown.iedown.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'IEStartNative'         : GLIEDown2.IEStartNative,
                          }
        },

        # Gogago
        {
            'id'        : ( '7966A32A-5783-4F0B-824C-09077C023080', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Download'              : Gogago.Download,
                          }
        },

        # GomWeb
        {
            'id'        : ( 'DC07C721-79E0-4BD4-A89F-C90871946A31', ),
            'name'      : ( 'gomwebctrl.gommanager.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'OpenURL'              : GomWeb.OpenURL,
                          }
        },

        # HPInfo
        {
            'id'        : ( '62DDEB79-15B2-41E3-8834-D3B80493887A',
                            '7CB9D4F5-C492-42A4-93B1-3F7D6946470D', ),
            'name'      : ( 'hpinfodll.hpinfo.1', 'hprulesengine.contentcollection.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'LaunchApp'             : HPInfo.LaunchApp,
                            'SetRegValue'           : HPInfo.SetRegValue,
                            'GetRegValue'           : HPInfo.GetRegValue,
                            'EvaluateRules'         : HPInfo.EvaluateRules,
                            'SaveToFile'            : HPInfo.SaveToFile,
                            'ProcessRegistryData'   : HPInfo.ProcessRegistryData,
                          }
        },

        # Icona SpA C6 Messenger
        {
            'id'        : ( 'C1B7E532-3ECB-4E9E-BB3A-2951FFE67C61', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {}
        },

        # ICQToolbar
        {
            'id'        : ( '855F3B16-6D32-4FE6-8A56-BBB695989046', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetPropertyById'       : ICQToolbar.GetPropertyById,
                          }
        },

        # IMWebControl
        {
            'id'        : ( '7C3B01BC-53A5-48A0-A43B-0C67731134B9', ),
            'name'      : ( 'imweb.imwebcontrol.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'ProcessRequestEx'      : IMWebControl.ProcessRequestEx,
                            'SetHandler'            : IMWebControl.SetHandler,
                          }
        },

        # IniWallet
        {
            'id'        : (),
            'name'      : ( 'iniwallet61.iniwallet61ctrl.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {},
        },


        # InternetCleverSuite
        {
            'id'        : ( 'E8F92847-7C21-452B-91A5-49D93AA18F30', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetToFile'             : InternetCleverSuite.GetToFile,
                          }
        },

        # JavaDeploymentToolkit
        {
            'id'        : ( 'CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA',
                            'CAFEEFAC-DEC7-0000-0001-ABCDEFFEDCBA',
                            '8AD9C840-044E-11D1-B3E9-00805F499D93', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'launch'                : JavaDeploymentToolkit.launch,
                            'launchApp'             : JavaDeploymentToolkit.launchApp,
                          },
        },

        # JavaPlugin
        {
            'id'        : (),
            'name'      : ( 'javaplugin', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {}
        },

        # JavaWebStart.isInstalled
        {
            'id'        : (),
            'name'      : ( 'javawebstart.isinstalled', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {}
        },

        # JetAudioDownloadFromMusicStore
        {
            'id'        : ( '8D1636FD-CA49-4B4E-90E4-0A20E03A15E8', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DownloadFromMusicStore' :  JetAudioDownloadFromMusicStore.DownloadFromMusicStore,
                          }
        },

        # Kingsoft
        {
            'id'        : ( 'D82303B7-A754-4DCB-8AFC-8CF99435AACE', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'SetUninstallName'      :  Kingsoft.SetUninstallName,
                          }
        },

        # MacrovisionFlexNet
        {
            'id'        : ( 'FCED4482-7CCB-4E6F-86C9-DCB22B52843C',
                            '85A4A99C-8C3D-499E-A386-E0743DFF8FB7',
                            'E9880553-B8A7-4960-A668-95C68BED571E',),
            'name'      : (),
            'attrs'     : {
                            'ScheduleInterval'      : 0},
            'funcattrs' : {},
            'methods'   : {
                            'Initialize'            : MacrovisionFlexNet.Initialize,
                            'CreateJob'             : MacrovisionFlexNet.CreateJob,
                            'DownloadAndExecute'    : MacrovisionFlexNet.DownloadAndExecute,
                            'DownloadAndInstall'    : MacrovisionFlexNet.DownloadAndInstall,
                            'AddFileEx'             : MacrovisionFlexNet.AddFileEx,
                            'AddFile'               : MacrovisionFlexNet.AddFile,
                            'SetPriority'           : MacrovisionFlexNet.SetPriority,
                            'SetNotifyFlags'        : MacrovisionFlexNet.SetNotifyFlags,
                            'RunScheduledJobs'      : MacrovisionFlexNet.RunScheduledJobs,
                          }
        },

        # MicrosoftWorks7Attack
        {
            'id'        : ( '00E1DB59-6EFD-4CE7-8C0A-2DA3BCAAD9C6',  ),
            'name'      : (),
            'attrs'     : {
                            'WksPictureInterface'       : 0,
                          },
            'funcattrs' : {
                            'WksPictureInterface'       : MicrosoftWorks7Attack.SetWksPictureInterface,
                          },
            'methods'   : {
                            'SetWksPictureInterface'    : MicrosoftWorks7Attack.SetWksPictureInterface,
                          }
        },

        # MicrosoftXMLDOM
        {
            'id'        : (),
            'name'      : ( 'microsoft.xmldom', 'msxml2.domdocument.3.0', ),
            'attrs'     : {
                            'async'            : False,
                            'parseError'       : XMLDOMParseError.XMLDOMParseError(),
                          },
            'funcattrs' : {},
            'methods'   : {
                            'loadXML'          : MicrosoftXMLDOM.loadXML,
                            'createElement'    : MicrosoftXMLDOM.createElement,
                          }
        },

        # MicrosoftXMLHTTP
        {
            'id'        : (),
            'name'      : (
                            'msxml2.xmlhttp',
                            'microsoft.xmlhttp',
                            'msxml2.xmlhttp.6.0',
                            'winhttp.winhttprequest.5.1',
                          ),
            'attrs'     : {
                            'bstrMethod'            : '',
                            'bstrUrl'               : '',
                            'varAsync'              : True,
                            'varUser'               : None,
                            'varPassword'           : None,
                            'status'                : 200,
                            'statusText'            : '200',
                            'requestHeaders'        : {},
                            'responseHeaders'       : {},
                            'responseBody'          : '',
                            'responseText'          : '',
                            'responseType'          : '',
                            'responseXML'           : '',
                            'response'              : '',
                            'readyState'            : 4,
                            'timeout'               : 0,
                            'mimeType'              : '',
                            'onerror'               : None,
                            'onload'                : None,
                            'onloadstart'           : None,
                            'onprogress'            : None,
                            'onreadystatechange'    : None,
                            'onabort'               : None,
                            'ontimeout'             : None,
                            'withCredentials'       : False,
                          },
            'funcattrs' : {},
            'methods'   : {
                            'abort'                 : MicrosoftXMLHTTP.abort,
                            'open'                  : MicrosoftXMLHTTP.open,
                            'send'                  : MicrosoftXMLHTTP.send,
                            'setRequestHeader'      : MicrosoftXMLHTTP.setRequestHeader,
                            'getResponseHeader'     : MicrosoftXMLHTTP.getResponseHeader,
                            'getAllResponseHeaders' : MicrosoftXMLHTTP.getAllResponseHeaders,
                            'overrideMimeType'      : MicrosoftXMLHTTP.overrideMimeType,
                            'addEventListener'      : MicrosoftXMLHTTP.addEventListener,
                            'removeEventListener'   : MicrosoftXMLHTTP.removeEventListener,
                            'dispatchEvent'         : MicrosoftXMLHTTP.dispatchEvent,
                            'waitForResponse'       : MicrosoftXMLHTTP.waitForResponse
                          }
        },

        # Move
        {
            'id'        : ( '6054D082-355D-4B47-B77C-36A778899F48', ),
            'name'      : ( 'qmpupgrade.upgrade.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Upgrade'       :   Move.Upgrade,
                          }
        },

        # MSRICHTXT
        {
            'id'        : ( '3B7C8860-D78F-101B-B9B5-04021C009402',
                            'B617B991-A767-4F05-99BA-AC6FCABB102E' ),
            'name'      : (),
            'attrs'     : { 'Text'          : '' },
            'funcattrs' : {},
            'methods'   : {
                            'SaveFile'      : MSRICHTXT.SaveFile,
                          }
        },

        # MSVFP
        {
            'id'        : ( 'A7CD2320-6117-11D7-8096-0050042A4CD2',
                            '008B6010-1F3D-11D1-B0C8-00A0C9055D74', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'foxcommand'    : MSVFP.foxcommand,
                            'FoxCommand'    : MSVFP.foxcommand,
                            'DoCmd'         : MSVFP.foxcommand,
                            'docmd'         : MSVFP.foxcommand,
                          }
        },

        # MSXML2.DOMDocument
        {
            'id'        : ( 'F6D90F11-9C73-11D3-B32E-00C04F990BB4', ),
            'name'      : ( 'msxml2.domdocument', 'msxml2.domdocument.6.0'),
            'attrs'     : {
                            'object'        : MSXML2DOMDocument,
                          },
            'funcattrs' : {},
            'methods'   : {
                            'definition'    : MSXML2DOMDocument.definition,
                          },
        },

        # MyspaceUploader
        {
            'id'        : ( '48DD0448-9209-4F81-9F6D-D83562940134', ),
            'name'      : ( 'aurigma.imageuploader.4.1', ),
            'attrs'     : {
                            'Action'        : ''},
            'funcattrs' : {
                            'Action'        : MyspaceUploader.SetAction,
                          },
            'methods'   : {
                            'SetAction'     : MyspaceUploader.SetAction,
                          }
        },

        # NamoInstaller
        {
            'id'        : ( 'AF465549-1D22-4140-A273-386FA8877E0A',  ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Install'       : NamoInstaller.Install,
                          }
        },

        # NCTAudioFile2
        {
            'id'        : ( '77829F14-D911-40FF-A2F0-D11DB8D6D0BC', ),
            'name'      : ( 'nctaudiofile2.audiofile.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'SetFormatLikeSample'   :   NCTAudioFile2.SetFormatLikeSample,
                          }
        },

        # NeoTracePro
        {
            'id'        : ( '3E1DD897-F300-486C-BEAF-711183773554',  ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'TraceTarget'           : NeoTracePro.TraceTarget,
                          }
        },

        # NessusScanCtrl
        {
            'id'        : ( 'A47D5315-321D-4DEE-9DB3-18438023193B', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'deleteReport'          : NessusScanCtrl.deleteReport,
                            'deleteNessusRC'        : NessusScanCtrl.deleteNessusRC,
                            'saveNessusRC'          : NessusScanCtrl.saveNessusRC,
                            'addsetConfig'          : NessusScanCtrl.addsetConfig,
                          }
        },

        # OfficeOCX
        {
            'id'        : ( '97AF4A45-49BE-4485-9F55-91AB40F288F2',  # Office
                            '97AF4A45-49BE-4485-9F55-91AB40F22B92',  # PowerPoint
                            '97AF4A45-49BE-4485-9F55-91AB40F22BF2',  # Word
                            '18A295DA-088E-42D1-BE31-5028D7F9B965',  # Excel
                          ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'OpenWebFile'           : OfficeOCX.OpenWebFile,
                          }
        },

        # OurgameGLWorld
        {
            'id'        : ( '61F5C358-60FB-4A23-A312-D2B556620F20', ),
            'name'      : ( 'hangameplugincn18.hangameplugincn18.1'),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'hgs_startGame'         : OurgameGLWorld.hgs_startGame,
                            'hgs_startNotify'       : OurgameGLWorld.hgs_startNotify,
                          }
        },

        # PPlayer
        {
            'id'        : ( 'F3E70CEA-956E-49CC-B444-73AFE593AD7F',
                            '5EC7C511-CD0F-42E6-830C-1BD9882F3458', ),
            'name'      : ( 'pplayer.xpplayer.1', ),
            'attrs'     : {
                            'FlvPlayerUrl'      : '',
                            'Logo'              : '',
                          },
            'funcattrs' : {
                            'FlvPlayerUrl'      : PPlayer.SetFlvPlayerUrl,
                            'Logo'              : PPlayer.SetLogo,
                          },
            'methods'   : {
                            'DownURL2'          : PPlayer.DownURL2,
                            'SetFlvPlayerUrl'   : PPlayer.SetFlvPlayerUrl,
                            'SetLogo'           : PPlayer.SetLogo,
                          }
        },

        # PTZCamPanel
        {
            'id'        : ( 'A86934DA-C3D6-4C1C-BD83-CA4F14B362DE', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'ConnectServer'     : PTZCamPanel.ConnectServer,
                          }
        },

        # QuantumStreaming
        {
            'id'        : ( 'E473A65C-8087-49A3-AFFD-C5BC4A10669B', ),
            'name'      : ( 'qsp2ie.qsp2ie', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'UploadLogs'        : QuantumStreaming.UploadLogs,
                          }
        },

        # QvodCtrl
        {
            'id'        : ( 'F3D0D36F-23F8-4682-A195-74C92B03D4AF', ),
            'name'      : ( 'qvodinsert.qvodctrl.1', ),
            'attrs'     : {
                            'URL'               : '',
                            'url'               : '',
                          },
            'funcattrs' : {
                            'URL'               : QvodCtrl.SetURL,
                            'url'               : QvodCtrl.SetURL,
                          },
            'methods'   : {
                            'SetURL'            : QvodCtrl.SetURL,
                          }
        },

        # RDS.DataSpace
        {
            'id'        : ( 'BD96C556-65A3-11D0-983A-00C04FC29E36',
                            'BD96C556-65A3-11D0-983A-00C04FC29E30',
                            'AB9BCEDD-EC7E-47E1-9322-D4A210617116',
                            '0006F033-0000-0000-C000-000000000046',
                            '0006F03A-0000-0000-C000-000000000046',
                            '7F5B7F63-F06F-4331-8A26-339E03C0AE3D',
                            '06723E09-F4C2-43c8-8358-09FCD1DB0766',
                            '639F725F-1B2D-4831-A9FD-874847682010',
                            'BA018599-1DB3-44f9-83B4-461454C84BF8',
                            'D0C07D56-7C69-43F1-B4A0-25F5A11FAB19',
                            'E8CCCDDF-CA28-496b-B050-6C07C962476B',
                            '6E32070A-766D-4EE6-879C-DC1FA91D2FC3',
                            '6414512B-B978-451D-A0D8-FCFDF33E833C'),
            'name'      : ( 'rdsdataspace', 'rds.dataspace', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'CreateObject'  : RDSDataSpace.CreateObject,
                          }
        },

        # RealPlayer
        {
            'id'        : ( 'FDC7A535-4070-4B92-A0EA-D9994BCC0DC5',
                            '2F542A2E-EDC9-4BF7-8CB1-87C9919F7F93',
                            '0FDF6D6B-D672-463B-846E-C6FF49109662',
                            '224E833B-2CC6-42D9-AE39-90B6A38A4FA2',
                            '3B46067C-FD87-49B6-8DDD-12F0D687035F',
                            '3B5E0503-DE28-4BE8-919C-76E0E894A3C2',
                            '44CCBCEB-BA7E-4C99-A078-9F683832D493',
                            'A1A41E11-91DB-4461-95CD-0C02327FD934',
                            'CFCDAA03-8BE4-11CF-B84B-0020AFBBCCFA', ),
            'name'      : ( 'ierpctl.ierpctl', 'ierpctl.ierpctl.1', ),
            'attrs'     : {
                            'Console'               : '',
                          },
            'funcattrs' : {
                            'Console'               : RealPlayer.SetConsole,
                          },
            'methods'   : {
                            'DoAutoUpdateRequest'   : RealPlayer.DoAutoUpdateRequest,
                            'PlayerProperty'        : RealPlayer.PlayerProperty,
                            'Import'                : RealPlayer.Import,
                            'SetConsole'            : RealPlayer.SetConsole,
                          }
        },

        # RediffBolDownloaderAttack
        {
            'id'        : ( 'BADA82CB-BF48-4D76-9611-78E2C6F49F03', ),
            'name'      : (),
            'attrs'     : {
                            'url'       : '',
                            'start'     : '',
                            'fontsize'  : 14,
                            'barcolor'  : 'EE4E00',
                          },
            'funcattrs' : {
                            'url'       : RediffBolDownloaderAttack.Seturl,
                          },
            'methods'   : {
                            'Seturl'    : RediffBolDownloaderAttack.Seturl,
                          }
        },

        # RegistryPro
        {
            'id'        : ( 'D5C839EB-DA84-4F98-9D42-2074C2EE9EFC', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DeleteKey'     : RegistryPro.DeleteKey,
                            'About'         : RegistryPro.About,
                          }
        },

        # RisingScanner
        {
            'id'        : ( 'E4E2F180-CB8B-4DE9-ACBB-DA745D3BA153', ),
            'name'      : (),
            'attrs'     : {
                            'BaseURL'       : '',
                            'Encardid'      : '',
                          },
            'funcattrs' : {},
            'methods'   : {
                            'UpdateEngine'  : RisingScanner.UpdateEngine,
                          }
        },

        # RtspVaPgCtrl
        {
            'id'        : ( '361E6B79-4A69-4376-B0F2-3D1EBEE9D7E2', ),
            'name'      : ( 'rtspvapgdecoder.rtspvapgctrl.1', ),
            'attrs'     : {
                            'MP4Prefix'         : '',
                          },
            'funcattrs' : {
                            'MP4Prefix'         : RtspVaPgCtrl.SetMP4Prefix,
                          },
            'methods'   : {
                            'SetMP4Prefix'      : RtspVaPgCtrl.SetMP4Prefix,
                          }
        },

        # Scripting.Encoder
        {
            'id'        : (),
            'name'      : ( 'scripting.encoder', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'EncodeScriptFile'  : ScriptingEncoder.EncodeScriptFile,
                          }
        },

        # Scripting.FileSystemObject
        {
            'id'        : (),
            'name'      : ( 'scripting.filesystemobject', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'BuildPath'         : ScriptingFileSystemObject.BuildPath,
                            'CopyFile'          : ScriptingFileSystemObject.CopyFile,
                            'CreateTextFile'    : ScriptingFileSystemObject.CreateTextFile,
                            'DeleteFile'        : ScriptingFileSystemObject.DeleteFile,
                            'FileExists'        : ScriptingFileSystemObject.FileExists,
                            'FolderExists'      : ScriptingFileSystemObject.FolderExists,
                            'GetExtensionName'  : ScriptingFileSystemObject.GetExtensionName,
                            'GetFile'           : ScriptingFileSystemObject.GetFile,
                            'GetSpecialFolder'  : ScriptingFileSystemObject.GetSpecialFolder,
                            'GetTempName'       : ScriptingFileSystemObject.GetTempName,
                            'MoveFile'          : ScriptingFileSystemObject.MoveFile,
                            'OpenTextFile'      : ScriptingFileSystemObject.OpenTextFile,
                          },
        },

        # Shell.Application
        {
            'id'        : (),
            'name'      : ( 'shell.application', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'ShellExecute'  : ShellApplication.ShellExecute,
                            'shellexecute'  : ShellApplication.ShellExecute,
                          }
        },

        # Shockwave
        {
            'id'        : ( '233C1507-6A77-46A4-9443-F871F945D258', ),
            'name'      : ( 'swctl.swctl', 'swctl.swctl.8',  ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'ShockwaveVersion'   : Shockwave.ShockwaveVersion,
                          }
        },

        # ShockwaveFlash.ShockwaveFlash.9
        {
            'id'        : (),
            'name'      : ( 'shockwaveflash.shockwaveflash.9', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetVariable'   : ShockwaveFlash9.GetVariable,
                          }
        },

        # ShockwaveFlash.ShockwaveFlash.10
        {
            'id'        : (),
            'name'      : ( 'shockwaveflash.shockwaveflash.10', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetVariable'   : ShockwaveFlash10.GetVariable,
                          }
        },

        # ShockwaveFlash.ShockwaveFlash.11
        {
            'id'        : (),
            'name'      : ( 'shockwaveflash.shockwaveflash.11', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetVariable'   : ShockwaveFlash11.GetVariable,
                          }
        },

        # ShockwaveFlash.ShockwaveFlash.12
        {
            'id'        : (),
            'name'      : ( 'shockwaveflash.shockwaveflash.12', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetVariable'   : ShockwaveFlash12.GetVariable,
                          }
        },

        # SiClientAccess
        {
            'id'        : (),
            'name'      : ( 'siclientaccess.siclientaccess.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {},
        },

        # SilverLight
        {
            'id'        : (),
            'name'      : ( 'agcontrol.agcontrol', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'isVersionSupported' : SilverLight.isVersionSupported,
                          }
        },

        # SinaDLoader
        {
            'id'        : ( '78ABDC59-D8E7-44D3-9A76-9A0918C52B4A', ),
            'name'      : ( 'downloader.dloader.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DownloadAndInstall'   : SinaDLoader.DownloadAndInstall,
                          }
        },


        # SnapshotViewer
        {
            'id'        : ( 'F0E42D60-368C-11D0-AD81-00A0C90DC8D9',
                            'F2175210-368C-11D0-AD81-00A0C90DC8D9' ),
            'name'      : ( 'snpvw.snapshot viewer control.1'),
            'attrs'     : {
                            'SnapshotPath'          : '',
                            'CompressedPath'        : '',
                          },
            'funcattrs' : {},
            'methods'   : {
                            'PrintSnapshot'         : SnapshotViewer.PrintSnapshot,
                          }
        },

        # SonicWallNetExtenderAddRouteEntry
        {
            'id'        : ( '6EEFD7B1-B26C-440D-B55A-1EC677189F30', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'AddRouteEntry'   : SonicWallNetExtenderAddRouteEntry.AddRouteEntry,
                          }
        },

        # Spreadsheet
        {
            'id'        : ( '0002E543-0000-0000-C000-000000000046',
                            '0002E55B-0000-0000-C000-000000000046' ),
            'name'      : ( 'owc10.spreadsheet',
                            'owc11.spreadsheet'),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Evaluate'              : Spreadsheet.Evaluate,
                            '_Evaluate'             : Spreadsheet._Evaluate,
                          }
        },

        # SSReaderPdg2
        {
            'id'        : ( '7F5E27CE-4A5C-11D3-9232-0000B48A05B2', ),
            'name'      : ( 'pdg2', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Register'              : SSReaderPdg2.Register,
                            'LoadPage'              : SSReaderPdg2.LoadPage,
                          }
        },

        # StormConfig
        {
            'id'        : ( 'BD103B2B-30FB-4F1E-8C17-D8F6AADBCC05', ),
            'name'      : ( 'config', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'SetAttributeValue'     : StormConfig.SetAttributeValue,
                          }
        },

        # StormMps
        {
            'id'        : ( '6BE52E1D-E586-474F-A6E2-1A85A9B4D9FB', ),
            'name'      : ( 'mps.stormplayer.1', ),
            'attrs'     : {
                            'URL'                   : '',
                            'backImage'             : '',
                            'titleImage'            : '',

                          },
            'funcattrs' : {
                            'URL'                   : StormMps.SetURL,
                            'backImage'             : StormMps.SetbackImage,
                            'titleImage'            : StormMps.SettitleImage,
                          },
            'methods'   : {
                            'advancedOpen'          : StormMps.advancedOpen,
                            'isDVDPath'             : StormMps.isDVDPath,
                            'rawParse'              : StormMps.rawParse,
                            'OnBeforeVideoDownload' : StormMps.OnBeforeVideoDownload,
                            'SetURL'                : StormMps.SetURL,
                            'SetbackImage'          : StormMps.SetbackImage,
                            'SettitleImage'         : StormMps.SettitleImage,
                          }
        },

        # SymantecAppStream
        {
            'id'        : ( '3356DB7C-58A7-11D4-AA5C-006097314BF8', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'installAppMgr'     : SymantecAppStream.installAppMgr,
                          }
        },

        # SymantecBackupExec
        {
            'id'        : ( '22ACD16F-99EB-11D2-9BB3-00400561D975', ),
            'name'      : ( 'pvatlcalendar.pvcalendar.1', ),
            'attrs'     : {
                            '_DOWText0'         : '',
                            '_DOWText6'         : '',
                            '_MonthText0'       : '',
                            '_MonthText11'      : '',
                          },
            'funcattrs' : {
                            '_DOWText0'         : SymantecBackupExec.Set_DOWText0,
                            '_DOWText6'         : SymantecBackupExec.Set_DOWText6,
                            '_MonthText0'       : SymantecBackupExec.Set_MonthText0,
                            '_MonthText11'      : SymantecBackupExec.Set_MonthText11,
                          },
            'methods'   : {
                            'Save'              : SymantecBackupExec.Save,
                            'Set_DOWText0'      : SymantecBackupExec.Set_DOWText0,
                            'Set_DOWText6'      : SymantecBackupExec.Set_DOWText6,
                            'Set_MonthText0'    : SymantecBackupExec.Set_MonthText0,
                            'Set_MonthText11'   : SymantecBackupExec.Set_MonthText11,
                          }
        },

        # StreamAudioChainCast
        {
            'id'        : ( '2253F320-AB68-4A07-917D-4F12D8884A06', ),
            'name'      : ( 'ccpm.proxymanager.1'),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'InternalTuneIn'    : StreamAudioChainCast.InternalTuneIn,
                          }
        },

        # Toshiba
        {
            'id'        : ( 'AD315309-EA00-45AE-9E8E-B6A61CE6B974', ),
            'name'      : ( 'meipcamx.recordsend.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'SetPort'               : Toshiba.SetPort,
                            'SetIpAddress'          : Toshiba.SetIpAddress,
                          }
        },

        # UniversalUpload
        {
            'id'        : ( '04FD48E6-0712-4937-B09E-F3D285B11D82', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'RemoveFileOrDir'       : UniversalUpload.RemoveFileOrDir,
                          }
        },

        # UUSeeUpdate
        {
            'id'        : ( '2CACD7BB-1C59-4BBB-8E81-6E83F82C813B', ),
            'name'      : ( 'uuupgrade.uuupgradectrl.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Update'                : UUSeeUpdate.Update,
                          }
        },

        # VisualStudio.DTE.8.0
        {
            'id'        : ( 'BA018599-1DB3-44F9-83B4-461454C84BF8', ),
            'name'      : ( ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'CreateObject'  : VisualStudioDTE80.CreateObject,
                          }
        },

        # VLC
        {
            'id'        : ( 'E23FE9C6-778E-49D4-B537-38FCDE4887D8', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'getVariable'           : VLC.getVariable,
                            'setVariable'           : VLC.setVariable,
                            'addTarget'             : VLC.addTarget,
                          }
        },

        # VsaIDE.DTE
        {
            'id'        : ( 'E8CCCDDF-CA28-496B-B050-6C07C962476B', ),
            'name'      : ( ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'CreateObject'  : VsaIDEDTE.CreateObject,
                          }
        },

        # VsmIDE.DTE
        {
            'id'        : ( '06723E09-F4C2-43C8-8358-09FCD1DB0766', ),
            'name'      : ( ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'CreateObject'  : VsmIDEDTE.CreateObject,
                          }
        },

        # WebViewFolderIcon
        {
            'id'        : (),
            'name'      : ( 'webviewfoldericon.webviewfoldericon.1', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'setSlice'              : WebViewFolderIcon.setSlice,
                          }
        },

        # WindowsMediaPlayer
        {
            'id'        : ( '22D6F312-B0F6-11D0-94AB-0080C74C7E95', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'Play'  : WindowsMediaPlayer.Play,
                          },
        },

        # WinNTSystemInfo
        {
            'id'        : ( '', ),
            'name'      : ( 'winntsysteminfo'),
            'attrs'     : {},
            'funcattrs' : {
                            'ComputerName'  : WinNTSystemInfo.GetComputerName,
                            'DomainName'    : WinNTSystemInfo.GetDomainName,
                            'PDC'           : WinNTSystemInfo.GetPDC,
                            'UserName'      : WinNTSystemInfo.GetUserName,
                          },
            'methods'   : {
                            'GetComputerName'  : WinNTSystemInfo.GetComputerName,
                            'GetDomainName'    : WinNTSystemInfo.GetDomainName,
                            'GetPDC'           : WinNTSystemInfo.GetPDC,
                            'GetUserName'      : WinNTSystemInfo.GetUserName,
                          },
        },

        # WinZip
        {
            'id'        : ( 'A09AE68F-B14D-43ED-B713-BA413F034904', ),
            'name'      : ( 'wzfileview.fileviewctrl.61'),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'CreateNewFolderFromName'   : WinZip.CreateNewFolderFromName,
                          }
        },

        # WMEncProfileManager
        {
            'id'        : ( 'A8D3AD02-7508-4004-B2E9-AD33F087F43C', ),
            'name'      : ( 'wmencprofilemanager', ),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetDetailsString'          : WMEncProfileManager.GetDetailsString,
                          }
        },

        # WMP
        {
            'id'        : ( '6BF52A52-394A-11D3-B153-00C04F79FAA6', ),
            'name'      : (),
            'attrs'     : { 'versionInfo'           : 10},
            'funcattrs' : {},
            'methods'   : {
                            'openPlayer'            : WMP.openPlayer,
                          }
        },

        # WScriptShell
        {
            'id'        : (),
            'name'      : 'wscript.shell',
            'attrs'     : {
                            'CurrentDirectory'          : 'C:\\Program Files',
                          },
            'funcattrs' : {},
            'methods'   :
                          {
                            'Run'                       : WScriptShell.Run,
                            '_doRun'                    : WScriptShell._doRun,
                            'Environment'               : WScriptShell.Environment,
                            'ExpandEnvironmentStrings'  : WScriptShell.ExpandEnvironmentStrings,
                            'CreateObject'              : WScriptShell.CreateObject,
                            'Sleep'                     : WScriptShell.Sleep,
                            'Quit'                      : WScriptShell.Quit,
                            'Echo'                      : WScriptShell.Echo,
                            'valueOf'                   : WScriptShell.valueOf,
                            'toString'                  : WScriptShell.toString,
                            'SpecialFolders'            : WScriptShell.SpecialFolders,
                            'CreateShortcut'            : WScriptShell.CreateShortcut,
                            'RegRead'                   : WScriptShell.RegRead,
                            'RegWrite'                  : WScriptShell.RegWrite,
                            'Popup'                     : WScriptShell.Popup
                          }
        },

        # WScriptShortcut
        {
        'id'        : (),
        'name'      : ( 'wscript.shortcut'),
        'attrs'     : {
                        'FullName'              : '',
                        'TargetPath'            : '',
                        'Description'           : '',
                        'Hotkey'                : '',
                        'IconLocation'          : '',
                        'RelativePath'          : '',
                        'WindowStyle'           : 1,
                        'WorkingDirectory'      : '',
                      },
        'funcattrs' : {},
        'methods'   : {
                        'save'                  : WScriptShortcut.save,
                      }
        },

        # WScriptNetwork
        {
        'id'        : (),
        'name'      : ('wscript.network'),
        'attrs'     : {},
        'funcattrs' : {
                        'ComputerName'          : WScriptNetwork.GetComputerName,
                        'UserDomain'            : WScriptNetwork.GetUserDomain,
                        'UserName'              : WScriptNetwork.GetUserName,
        },
        'methods'   : {
                        'EnumPrinterConnections': WScriptNetwork.EnumPrinterConnections,
                        'EnumNetworkDrives'     : WScriptNetwork.EnumNetworkDrives,
                        'GetComputerName'       : WScriptNetwork.GetComputerName,
                        'GetUserDomain'         : WScriptNetwork.GetUserDomain,
                        'GetUserName'           : WScriptNetwork.GetUserName,
                      }
        },

        # XUpload
        {
            'id'        : ( 'E87F6C8E-16C0-11D3-BEF7-009027438003', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'AddFolder'             : XUpload.AddFolder,
                            'AddFile'               : XUpload.AddFile,
                          }
        },

        # YahooJukebox
        {
            'id'        : ( '22FD7C0A-850C-4A53-9821-0B0915C96139',
                            '5F810AFC-BB5F-4416-BE63-E01DD117BD6C'),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'AddBitmap'             : YahooJukebox.AddBitmap,
                            'AddButton'             : YahooJukebox.AddButton,
                            'AddImage'              : YahooJukebox.AddImage,
                          }
        },

        # YahooMessengerCyft
        {
            'id'        : ( '24F3EAD6-8B87-4C1A-97DA-71C126BDA08F', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'GetFile'               : YahooMessengerCyft.GetFile,
                          }
        },

        # YahooMessengerYVerInfo
        {
            'id'        : ( 'D5184A39-CBDF-4A4F-AC1A-7A45A852C883', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'fvcom'                 : YahooMessengerYVerInfo.fvcom,
                            'info'                  : YahooMessengerYVerInfo.info,
                          }
        },

        # YahooMessengerYwcvwr
        {
            'id'        : ( '9D39223E-AE8E-11D4-8FD3-00D0B7730277',
                            'DCE2F8B1-A520-11D4-8FD0-00D0B7730277',
                            '7EC7B6C5-25BD-4586-A641-D2ACBB6629DD'),
            'name'      : (),
            'attrs'     : {
                            'server'                : ''
                          },
            'funcattrs' : {
                            'server'                : YahooMessengerYwcvwr.Setserver,
                          },
            'methods'   : {
                            'Setserver'             : YahooMessengerYwcvwr.Setserver,
                            'GetComponentVersion'   : YahooMessengerYwcvwr.GetComponentVersion,
                            'initialize'            : YahooMessengerYwcvwr.initialize,
                            'send'                  : YahooMessengerYwcvwr.send,
                            'receive'               : YahooMessengerYwcvwr.receive,
                          }
        },

        # ZenturiProgramCheckerAttack
        {
            'id'        : ( '59DBDDA6-9A80-42A4-B824-9BC50CC172F5', ),
            'name'      : (),
            'attrs'     : {},
            'funcattrs' : {},
            'methods'   : {
                            'DownloadFile'          : ZenturiProgramCheckerAttack.DownloadFile,
                            'DebugMsgLog'           : ZenturiProgramCheckerAttack.DebugMsgLog,
                            'NavigateUrl'           : ZenturiProgramCheckerAttack.NavigateUrl,
                          }
        },
]
