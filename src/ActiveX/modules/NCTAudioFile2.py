# NCTsoft Products NCTAudioFile2 ActiveX Control
# CVE-2007-0018

def SetFormatLikeSample(arg):
	if len(arg) > 4000:
		add_alert('NCTAudioFile2 overflow in SetFormatLikeSample')

self.SetFormatLikeSample = SetFormatLikeSample
