def LaunchGui(arg0,arg1,arg2):
	if len(arg0)>1500:
		add_alert('EnjoySAP.LaunchGUI overflow in arg0')

def PrepareToPostHTML(arg):
	if len(arg)>1000:
		add_alert('EnjoySAP.PrepareToPostHTML overflow in arg0')


self.LaunchGui=LaunchGui
self.PrepareToPostHTML=PrepareToPostHTML
