// Blackhole 2.0 Exploit Kit (rule #1)
rule Blackhole_V2_1 : Exploit_Kit
{
  meta:
    author = "Thorsten Sick"
  strings:
    $url = ".ru:8080/forum/links/column.php" nocase
  condition:
    $url
}


// Blackhole 2.0 Exploit Kit (rule #2) 
rule Blackhole_V2_2 : Exploit_Kit
{
  meta:
    author = "Thorsten Sick"
  strings:
    $url = /\/closest\/\w{15,35}\.php/ nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #3) 
rule Blackhole_V2_3 : Exploit_Kit
{
  meta:
    author = "Thorsten Sick"
  strings:
    $url = ".ru:8080/forum/links/public_version.php" nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #4)
rule Blackhole_V2_4 : Exploit_Kit
{
  meta:
    author = "MalwareSigs" 
  strings:
    $url = /\/(black_dragon|98y7y432ufh49gj23sldkkqowpsskfnv|98yf8913fjipgjialhg8239jgighnjh4i6k5o|209tuj2dsljdglsgjwrigslgkjskga|984y3fh8u3hfu3jcihei)\.php/ nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #5) 
rule Blackhole_V2_5 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"  
  strings:
    $url = /\/(sort|info\/last\/index)\.php/ nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #6)
rule Blackhole_V2_6 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /:8080\/[a-zA-Z0-9\/]+\.php/ nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #7)
rule Blackhole_V2_7 : Exploit_Kit
{                        
  meta:                
    author = "MalwareSigs"
  strings:             
    $url = /\/[a-f0-9]{16,32}\/[a-z]+\.php/ nocase
  condition:      
    $url                            
}   


//Blackhole 2.0 Exploit Kit (rule #8)
rule Blackhole_V2_8 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = "/ngen/controlling/" nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #9)
rule Blackhole_V2_9 : EOT_exploit Exploit_Kit
{
  meta:
    author = "MalwareSigs"
    //cve    = "CVE-2011-3402"
  strings:
    $url = "/shrift.php" nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #10)
rule Blackhole_V2_10 : Java_exploit Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\.php\?[a-z]{3,8}=[a-z]{3,8}&[a-z]{3,8}=[a-z]{3,8}$/ nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #11)
rule Blackhole_V2_11 : PDF_or_SWF_or_EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /([1-3][a-z0-9]:){9}[1-3][a-z0-9]/ nocase
  condition:
    $url
}


//Blackhole 2.0 Exploit Kit (rule #12)
rule Blackhole_V2_12 : Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = /\.php\?.*\?\:[a-zA-Z0-9\:]{6,}\&.*\?\&/
  condition:
    $a
}


//Blackhole 2.0 Exploit Kit (rule #13)
rule Blackhole_V2_13 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = /\.php\?[a-zA-Z]{2,6}\=[A-Za-z0-9]{10,}\&[A-Za-z]{2,}\=[A-Za-z0-9]{10,}\&[A-Za-z]{1,}\=[A-Fa-f0-9]{2,}\&[A-Za-z]{2,}\=[A-Za-z0-9]+\&[A-Za-z0-9]{1,}\=[A-Za-z]{1,}/
  condition:
    $a
}
