# NCTsoft Products NCTAudioFile2 ActiveX Control
# CVE-2007-0018

acct = ActiveXAcct[self]

def SetFormatLikeSample(arg):
    global acct

    if len(arg) > 4000:
        acct.add_alert('NCTAudioFile2 overflow in SetFormatLikeSample')

self.SetFormatLikeSample = SetFormatLikeSample
