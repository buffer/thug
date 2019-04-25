
import string
import random
import logging

log = logging.getLogger("Thug")


def GetComputerName(self):
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting ComputerName")

    nlen = random.randint(6, 10)
    computerName = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return computerName


def GetDomainName(self):
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting DomainName")

    nlen = random.randint(6, 10)
    domainName = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return domainName


def GetPDC(self):
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting PDC (Primary Domain Controller)")

    nlen = random.randint(6, 10)
    pdc = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return pdc


def GetUserName(self):
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting UserName")

    nlen = random.randint(6, 10)
    userName = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return userName
