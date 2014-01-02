// Nuclear Exploit Kit (rule #1)
rule Nuclear_1 : Landing Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-f0-9]{32}\.html$/ nocase
  condition:
    $url
}


// Nuclear Exploit Kit (rule #2)
rule Nuclear_2 : JAR Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-f0-9]{32}\/[0-9]{10}\/[a-f0-9]{32}\.jar$/ nocase
  condition:
    $url
}


// Nuclear Exploit Kit (rule #3)
rule Nuclear_3 : EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-z]\/[0-9]{10}\/[a-f0-9]{32}\/[a-f0-9]{32}(\/[0-9]){1,2}$/ nocase
  condition:
    $url
}
