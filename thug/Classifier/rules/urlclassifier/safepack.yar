// Safepack Exploit Kit (rule #1)
rule Safepack_1 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = "load.php?e=" nocase
    $b = "&ip=" nocase
  condition:
    2 of ($a,$b)
}


// Safepack Exploit Kit (rule #2)
rule Safepack_2 : JAR Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = /\/j\d{2}\.php\?i\=[a-zA-Z0-9]{9,15}/ nocase
  condition:
    $a
}
