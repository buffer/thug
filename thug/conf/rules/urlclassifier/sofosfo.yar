// SofosFO Exploit Kit (rule #1) (rule #2)
rule SofosFO_1 : EXE Exploit_Kit
{	
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/[a-zA-Z0-9]{24,}\/[0-9]{9,10}\/[0-9]{7,10}\s/
  condition:
    $url
}


// SofosFO Exploit Kit (rule #2)
rule SofosFO_2 : Redirect Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\.php\?id\=\d+\&session\=[a-z0-9]{15,}\&ip\=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
  condition:
    $url
}
