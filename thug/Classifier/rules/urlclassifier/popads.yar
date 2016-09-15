// Popads Exploit Kit (rule #1) 
rule Popads_1 : Landing Exploit_Kit
{
  meta:
    author = "MalwareSigs"  
  strings:
    $url = /\/\?[a-f0-9]{32}=[a-z0-9]{2,3}(&[a-f0-9]{32}=[a-z0-9-_.]+)\?$/ nocase
  condition:
  $url
}


// Popads Exploit Kit (rule #2)
rule Popads_2 : EOT Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-f0-9]{32}\.eot$/ nocase
  condition:
    $url
}


// Popads Exploit Kit (rule #3)
rule Popads_3 : SWF Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-f0-9]{32}\/[a-f0-9]{32}\.swf$/ nocase
  condition:
    $url
}


// Popads Exploit Kit (rule #4)
rule Popads_4 : EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-f0-9]{32}\/[0-4]$/ nocase
  condition:
    $url
}


// Popads Exploit Kit (rule #5)
rule Popads_5 : JAR Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-f0-9]{32}\/[a-f0-9]{32}\.jar$/ nocase
  condition:
    $url
}
