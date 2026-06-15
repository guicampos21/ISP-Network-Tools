# Risk Model

## Final Classes

- `No risk`
- `Low`
- `Moderate`
- `High`
- `Very high`

## Final Rules

- A listed `ASN-DROP` result implies `Very high`.
- Any `NETWORK_SCOPE_BLACKLISTS` finding raises the report-wide risk to `Very high`.
- `DIRECT_IP_BLACKLISTS` evidence drives risk when there is no network/ASN signal.
- Informational sources can raise the report only to `Low` when they appear alone.
- Different zones from the same DNSBL family count as different blacklists, but not as independent families.
- Two `high` hits in the same family do not automatically promote an IP to `Very high`.
- Two `high` hits in independent families may promote an IP to `Very high`.
- One `very_high` hit, such as `zen.spamhaus.org`, still promotes the IP to `Very high`.
- Timeouts and errors never count as hits; they affect confidence only.

## Evidence Scope

- IP sources affect individual IP addresses.
- Network sources affect blocks, providers, or ASNs.
- Informational sources preserve technical context without contaminating the direct inventory.

## Derived Fields

- Per IP: `risk_level`, `risk_reason`, `confidence`, hit counters, affected families, and hit details.
- Report-wide: `report_risk_level`, `report_confidence`, `report_risk_reason`, affected IP ratio, affected families, severity counters, timeout counters, and error counters.
