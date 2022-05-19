// g01Pack Exploit Kit (rule #1)
rule g01Pack_1 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/\w+\.php\?[a-zA-Z0-9\%\&\=]+u\=\d{5,}\&/ nocase
  condition:
    $url
}


// g01Pack Exploit Kit (rule #2)
rule g01Pack_2 : Exploit_Kit
{
  meta:
    author = "MalwareSigs" 
  strings:
    $url = /\/(forum|mix|songs|ports|news|comments|top|funds|feeds|finance|usage|profile|points|look|banners|view|ads|delivery|paints|audit|css|accounts|internet|tweet)\// nocase
  condition:
    $url
}


// g01Pack Exploit Kit (rule #3)
rule g01Pack_3 : EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/(forum|mix|songs|ports|news|comments|top|funds|feeds|finance|usage|profile|points|look|banners|view|ads|delivery|paints|audit|css|accounts|internet|tweet)\/[a-z0-9]{5,14}\.php/ nocase
  condition:
    $url
}
