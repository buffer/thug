
acct   = ActiveXAcct[self]
object = self

def DownloadFile(*arg):
    global acct
    global object

    acct.add_alert('ZenturiProgramCheckerAttack attack in DownloadFile function')

    import os, hashlib, httplib2
    h = httplib2.Http('/tmp/.cache')

    headers = {
        'user-agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
    }

    #FIXME: Relative URLs
    response, content = h.request(arg[0], headers = headers)
    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    acct.add_alert("[*] Saving File: " + filename)
    
    with open(os.path.join(object._log.baseDir, filename), 'wb') as fd:
        fd.write(content)

def DebugMsgLog(*arg):
    global acct

    acct.add_alert('ZenturiProgramCheckerAttack attack in DebugMsgLog function')

def NavigateUrl(*arg):
    global acct

    acct.add_alert('ZenturiProgramCheckerAttack attack in NavigateUrl function')

self.DownloadFile = DownloadFile
self.DebugMsgLog  = DebugMsgLog
self.NavigateUrl  = NavigateUrl
