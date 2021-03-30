import logging
import random
import string

from thug.ActiveX.modules import WScriptShell
from thug.ActiveX.modules import WScriptCollection

log = logging.getLogger("Thug")


def EnumPrinterConnections(self):
    log.ThugLogging.add_behavior_warn("[WScript.Network ActiveX] Got request to PrinterConnections")

    printerlist = [['nul:', 'Send To OneNote 2010'],
                   ['XPSPort:', 'Microsoft XPS Document Writer'],
                   ['SHRFAX:', 'Fax']]

    for _ in range(3):
        ip = GetRandomIp()
        printerlist.append(['IP_{}'.format(ip), GetRandomShare(ip)])

    random.shuffle(printerlist)
    return WScriptCollection.WshCollection(sum(printerlist[:2], []))


def EnumNetworkDrives(self):
    log.ThugLogging.add_behavior_warn("[WScript.Network ActiveX] Got request to EnumNetworkDrives")
    ndrives = WScriptCollection.WshCollection()

    for _ in range(2):
        drive = "{}:".format(chr(random.choice(range(ord('E'), ord('Z')))))
        ndrives.extend([drive, GetRandomShare(GetRandomIp())])

    return ndrives


def GetRandomShare(location):
    share = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return "\\\\{}\\{}".format(location, share)


def GetRandomIp():
    ip = "192.168."
    ip += ".".join(map(str, (random.randint(0, 255) for _ in range(2))))
    return ip


def GetUserDomain(self):
    return WScriptShell.ExpandEnvironmentStrings(self, "%USERDOMAIN%")


def GetUserName(self):
    return WScriptShell.ExpandEnvironmentStrings(self, "%USERNAME%")


def GetComputerName(self):
    return WScriptShell.ExpandEnvironmentStrings(self, "%COMPUTERNAME%")
