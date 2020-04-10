rule image_filter_16
{
  meta:
    etags = "$brand"
  strings:
    $brand = "Antifork"
  condition:
    all of them
}
