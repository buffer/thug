rule url_signature_13
{
  meta:
    etags = "$url1"
  strings:
    $url1 = "antifork.org"
  condition:
    all of them
}
