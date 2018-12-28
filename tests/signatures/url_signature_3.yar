rule url_signature_3
{
  strings:
    $url1 = "www.antifork.org"
  condition:
    all of them
}
