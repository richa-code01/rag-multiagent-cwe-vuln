# Benchmark notices

The trees under this directory are the slices the evaluation scores, pinned to the commits recorded when those scores were measured. Nested `.git` directories are not part of this repository. Zip downloads stay gitignored.

| Slice | Source | Pinned commit | License |
| --- | --- | --- | --- |
| `juliet-java/` | NIST Juliet Java 1.3 via `https://github.com/find-sec-bugs/juliet-test-suite` (SARD 111). Mapped CWE folders plus `src/testcasesupport` only. | `b2c6df3733e2176fe7097e4784895c6891632b4c` | NIST SAMATE educational test suite. The mirror checkout has a README and no separate LICENSE file. |
| `owasp-benchmark/` | `https://github.com/OWASP-Benchmark/BenchmarkJava` testcode and `expectedresults-1.2.csv` | `20cbf3d11123347e47ed89541e6942836def53f7` | Upstream `LICENSE` vendored in that directory. |
| `securibench-micro/` | `https://github.com/too4words/securibench-micro` | `6a5a72488ea830d99f9464fc1f0562c4f864214b` | Apache-2.0. Copyright 2006 Benjamin Livshits / Stanford Securibench Micro. |
| `find-sec-bugs/` | `https://github.com/find-sec-bugs/find-sec-bugs` testcode | `90447f7e39e529c31cf098ebade0a755b944dd91` | LGPL. Upstream `LICENSE` vendored in that directory. |
| `vul4j/` and `vul4j-files/` | `https://github.com/tuhh-softsec/vul4j` CSV plus Java blobs from the scored upstream patch commits | `376411da11fa705019f731404de1d0679fe73537` | Vul4J metadata is GPLv3 (`vul4j/LICENSE`). Java files keep their upstream contents and are vendored so the scored rows can be reproduced. |
| `cvefixes-files/` | GitHub Security Advisories, ecosystem maven, 24-advisory slice. Not the CVEfixes Zenodo dump. | advisory manifest in `cvefixes_java_slice_manifest.json` | Java files are the public parent and patch blobs named in that manifest. |

Do not relabel nearby Juliet CWE ids. Do not treat these trees as a claim that regex SAST is CodeQL.
