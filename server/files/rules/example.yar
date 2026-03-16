rule Example_Suspicious_JS {
  meta:
    description = "Flags JS strings common in obfuscation"
    author = "elixir-analyzer"
  strings:
    $eval = "eval(" ascii nocase
    $atob = "atob(" ascii nocase
    $func = "Function(" ascii nocase
  condition:
    1 of ($eval,$atob,$func)
}
