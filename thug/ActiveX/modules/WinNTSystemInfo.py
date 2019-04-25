
import string
import random
import logging

log = logging.getLogger("Thug")


@property
def ComputerName():
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting ComputerName")

    nlen = random.randint(6, 10)
    computerName = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return computerName


@property
def DomainName():
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting DomainName")

    nlen = random.randint(6, 10)
    domainName = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return domainName


@property
def PDC():
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting PDC (Primary Domain Controller)")

    nlen = random.randint(6, 10)
    pdc = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return pdc


@property
def UserName():
    log.ThugLogging.add_behavior_warn("[WinNTSystemInfo ActiveX] Getting UserName")

    nlen = random.randint(6, 10)
    userName = ''.join(
        random.choice(
            string.ascii_letters + string.digits) for _ in range(nlen))

    return userName
