# Generated Authentication Assessment Scenario Corpus

This directory contains deterministic, local-only scenario records for load-free regression, parser, report, and policy validation. It does not implement credential attacks or target live systems. The corpus is generated to support scale testing of test discovery, evidence serialization, and reporting. Scenario values are synthetic and point only to the bundled demo lab.

Each module exposes `SCENARIOS`, a list of structured case records. Re-generate with `python scripts/generate_scenario_corpus.py`.
