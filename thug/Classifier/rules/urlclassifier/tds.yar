// Traffic Broker (rule #1)
rule Traffic_Broker_1 : TDS
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /rd\.php\?http/ nocase
  condition:
    $url
}


// Sutra (rule #1)
rule Sutra_1 : TDS
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/in\.cgi\?\d/ nocase
  condition:
    $url
}
