# Hard Fuzzing Roadblocks

- feedback tests KERNELAFL/KASAN/SERGEJ should be solved within few minutes

- LLOOPBACK is not solved in a targeted fashion but eventually (~10h)
  - it may be worth tuning the bitmap bucketing mechanism to address this

- LLOOPBACK also has an implicit magic byte check at the very start, solved easily

- HASH/checksum cases are not currently solved and deemed not worth solving.
  Redqueen v0.1 has some logic to find these, may be able to re-activate
  in Grimoire frontend (fix_hashes)
