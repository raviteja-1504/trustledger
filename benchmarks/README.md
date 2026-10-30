# Benchmark harness

How the numbers on [/benchmarks](https://dashboard-psi-smoky-96.vercel.app/benchmarks) are produced, so anyone
with this repository can reproduce them.

## Corpora

| Corpus | Version | Languages | Where to get it |
|---|---|---|---|
| OWASP-style SAST Benchmark (0llino) | Go 0.5.1, PHP 0.3.2, Ruby 0.3.2, Rust 0.5.2 | Go, PHP, Ruby, Rust | https://github.com/0llino/sast-benchmark |
| OWASP Benchmark for Java | 1.2 | Java | https://github.com/OWASP-Benchmark/BenchmarkJava |
| OWASP Benchmark for Python | 0.1 | Python | https://github.com/OWASP-Benchmark/BenchmarkPython |
| NIST SARD Juliet Test Suite for C# | as distributed by SARD (the archive carries no version number) | C# | https://samate.nist.gov/SARD/test-suites |
| NIST SARD Juliet Test Suite for C/C++ | 1.3 | C, C++ | https://samate.nist.gov/SARD/test-suites |
| OWASP Juice Shop | 20.3.0 | TypeScript/JavaScript | https://github.com/juice-shop/juice-shop |

Each corpus labels its test cases: a vulnerable case and a safe twin per vulnerability category (Juliet: a bad and
a good region in every case; Juice Shop: the `vuln-code-snippet vuln-line` markers in its own source).

## Running a corpus

The probes in `harness/` are Jest tests that call the production scanner (`runScan`) on a directory in batches, the
same way a pull request is scanned, and write every finding as a TSV row. They are stored as `.txt` so the normal
test run doesn't pick them up; copy one into `src/__tests__/` to use it:

```sh
cp benchmarks/harness/probe.test.ts.txt src/__tests__/zzProbe.test.ts        # directory probe (sast-benchmark, Juice Shop)
cp benchmarks/harness/juliet.test.ts.txt src/__tests__/zzJuliet.test.ts      # batched probe (Juliet C#, OWASP Benchmark)
cp benchmarks/harness/juliet-c.test.ts.txt src/__tests__/zzJulietC.test.ts   # Juliet C/C++

# e.g. sast-benchmark Go:
ROOT=/path/to/sast-benchmark/go EXT='\.go$' OUT=sb_go.tsv npx jest src/__tests__/zzProbe.test.ts

# e.g. OWASP Benchmark for Java, with its helper classes scanned alongside the test cases:
JROOT=/path/to/BenchmarkJava/src/main/java/org/owasp/benchmark CWES=testcode EXTRA=helpers \
  SRC='^BenchmarkTest' EXT='\.java$' OUT=benchjava.tsv npx jest src/__tests__/zzJuliet.test.ts
```

Delete the copied probes afterwards; they are not part of the test suite.

## Scoring

`scorers/` holds one script per corpus. Each reads the corpus's own labels and the probe TSV and prints a table of
true/false positives and negatives per category; with `JSON_OUT=<file>` it also writes those counts as JSON.

```sh
node benchmarks/scorers/score_sb.js /path/to/sast-benchmark/go/expectedresults-0.5.1.csv sb_go.tsv
node benchmarks/scorers/score_benchjava.js /path/to/BenchmarkJava/expectedresults-1.2.csv benchjava.tsv
node benchmarks/scorers/score_juliet.js /path/to/juliet-cs/src/testcases juliet_cs.tsv "CWE89_SQL_Injection/s01,..." '<file regex>' '\.cs$'
```

The score is TPR − FPR in percentage points (the OWASP Benchmark convention). The mapping from TrustLedger rule
ids to each corpus's categories is the `RULES` table at the top of each scorer.

## Building the report

`build-report.mjs <run.json>` runs every scorer with `JSON_OUT` and writes `src/data/benchmarks.json`. `run.json`
names the engine commit and, per corpus, the metadata, the TSV, the scorer arguments and the measured file count and
wall-clock time. Curated content — the false-positive and false-negative examples (each citing a corpus case id),
the known limitations, the comparison status and the history table — lives in `report-notes.json`.

## What is not measured yet

- **Trace accuracy**: no public corpus labels the expected source-to-sink path.
- **Other scanners**: CodeQL and Semgrep have not been run under identical conditions; no comparison is published
  until they have.
- **Kotlin / Android**: there is no public labelled corpus; the engine is tested against AndroGoat and Goatlin by
  hand and in unit tests, not scored.
