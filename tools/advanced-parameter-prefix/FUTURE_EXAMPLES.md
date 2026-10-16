# Future parameter examples

These cases are intentionally not active. When promoted, add each case to
`PARAMETER_EXAMPLES` and consume its generated fixture data from an Aiken
`const`.

| Area | Candidate values | Coverage goal |
| --- | --- | --- |
| Integer CBOR widths | `23`/`24`, `-24`/`-25`, `255`/`256`, `65_535`/`65_536` | Exercise every practical integer-header transition. |
| Byte-array CBOR widths | Payload lengths `23`/`24` and `255`/`256` | Exercise byte-array length-header transitions. |
| Constructor tags | Constructor indices `6`, `7`, and `127` | Cover the compact-tag boundaries below the active index-`128` case. |
| Empty and nested containers | Empty list, empty map, and a map containing an empty list | Cover definite/indefinite normalization of empty nested data. |
| Alternative source CBOR | Equivalent definite and indefinite list/map encodings supplied through an environment override | Verify normalization without losing the configured parameter meaning. |
| Outer script wrapper | Final Flat-script lengths `65_535`/`65_536` | Exercise the next definite-bytestring header width when a practical fixture is available. |
