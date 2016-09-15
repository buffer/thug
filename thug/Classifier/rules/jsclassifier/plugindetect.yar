rule PluginDetect : Multiple_Exploit_Kits
{
  meta:
    author  = "Angelo Dell'Aera"
  strings:
    $jar    = "getjavainfo.jar" nocase
    $pdpd   = "pdpd" nocase
    $getver = "getversion" nocase 
  condition:
    ($jar or $pdpd) and $getver
}
