

acct = ActiveXAcct[self]

def LaunchGui(arg0, arg1, arg2):
    global acct

    if len(arg0) > 1500:
        acct.add_alert('EnjoySAP.LaunchGUI overflow in arg0')

def PrepareToPostHTML(arg):
    global acct

    if len(arg) > 1000:
        acct.add_alert('EnjoySAP.PrepareToPostHTML overflow in arg0')

def Comp_Download(arg0, arg1):
    global acct

    acct.add_alert(arg0)
    acct.add_alert(arg1)

    headers = {
        'user-agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
    }

    import hashlib, httplib2
    h = httplib2.Http('/tmp/.cache')

    #FIXME: Relative URLs
    response, content = h.request(arg0, headers = headers)
    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    acct.add_alert("[*] Saving File: " + filename)
    
    with open(filename, 'wb') as fd:
        fd.write(content)


self.LaunchGui         = LaunchGui
self.PrepareToPostHTML = PrepareToPostHTML
self.Comp_Download     = Comp_Download
