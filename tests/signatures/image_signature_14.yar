rule image_signature_14
{
  meta:
    domain_whitelist = "google.com"
    etags = "$brand"
  strings:
    $brand = "Antifork"
  condition:
    all of them
}
