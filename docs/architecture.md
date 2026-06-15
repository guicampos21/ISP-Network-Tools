# Architecture

## Overview

INH is a Python CLI application with a readable runtime core in `src/inh/core.py` and an orchestration layer in `src/inh/cli.py`.

The CLI layer:

- imports the readable core directly as a Python module;
- applies runtime patches for reporting and risk analysis behavior;
- categorizes sources by scope;
- normalizes DNSBL response handling;
- recalculates risk using direct IP evidence, network context, and `ASN-DROP`;
- renders the consolidated HTML report;
- applies `pt-BR` and `en-US` localization according to the language confirmed by the user at startup;
- adds basic execution metadata to the HTML report and JSON summary.

## Components

- `src/inh/cli.py`: final CLI wrapper and public entry point.
- `src/inh/core.py`: readable application core.
- `src/inh/resources/help_text.txt`: detailed Portuguese CLI help text.
- `src/inh/resources/help_text_en.txt`: detailed English CLI help text.

## Flow

1. The user provides a domain, IPv4 address, IPv4 CIDR block, or ASN.
2. The CLI identifies the target type.
3. The core builds the query tasks.
4. The CLI remaps network-scope checks to block context when needed.
5. Results are classified as `direct`, `network`, `informational`, or `asn_drop`.
6. Per-IP and report-wide risk are recalculated.
7. HTML and JSON report artifacts are generated.

## Final Behavior

- The user can choose `conservative` or `aggressive` query mode.
- The final report is always the complete HTML report.
- The JSON summary separates direct IP risk, network context, and `ASN-DROP`.
- The `/24` block inventory is included in the report.
