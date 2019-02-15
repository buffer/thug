rule url_signature_3
{
  meta:
    domain_whitelist = "honeynet.org"
  strings:
    $url1 = "github.com"
  condition:
    all of them
}
