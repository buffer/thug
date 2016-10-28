import logging
import random
import string

log = logging.getLogger("Thug")

class WshCollection(list):
    def __getattr__(self, name):
        if name.lower() == 'length':
            return len(self)

    def Item(self, pos):
        return self[pos]

def EnumPrinterConnections(self):
    log.ThugLogging.add_behavior_warn("[WScript.Network ActiveX] Got request to PrinterConnections")
    return WshCollection(['nul:', 'Send To OneNote 2010',
                          'XPSPort:', 'Microsoft XPS Document Writer',
                          'SHRFAX:', 'Fax'])

def EnumNetworkDrives(self):
    log.ThugLogging.add_behavior_warn("[WScript.Network ActiveX] Got request to EnumNetworkDrives")
    ndrives = WshCollection()

    for _ in range(2):
        drive = "{}:".format(chr(random.choice(range(ord('E'), ord('Z')))))
        share = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))

        ip = "192.168."
        ip += ".".join(map(str, (random.randint(0, 255) for _ in range(2))))

        ndrives.extend([drive, "\\\\{}\\{}".format(ip, share)])

    return ndrives
