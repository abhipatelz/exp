# OpenGxP

Open-source, single-kernel software for regulated (GxP) life-science operations:
**LIMS + QMS + DMS + MES (eBR) + CSV** on one shared compliance core.

| Module | Commercial category it targets | What exists today |
|---|---|---|
| `lims` | LabWare / LabVantage-class LIMS | Specifications, sample lifecycle, result entry, automatic spec evaluation, OOS → deviation, 2nd-person review, QA approval |
| `qms`  | TrackWise-class QMS | Deviations, CAPA, change control, closure gated on CAPA completion |
| `dms`  | Documentum D2-class controlled documents | Draft → review → approve → effective, revisions, automatic supersession, retirement |
| `mes`  | PAS-X-class MES / electronic batch record | Master batch record, batch execution in enforced step order, per-step operator e-signature, process limits, excursion → deviation, review by exception, QA release |
| `csv`  | ValGenesis / Kneat-class paperless validation | System + validation plan, URS, test scripts, execution, test incidents, traceability matrix, release gated on full coverage |

Zero third-party dependencies: Python ≥ 3.10 standard library + SQLite.

## Design: one kernel, five thin modules

The commercial products above are sold separately, but ~80% of each is the same machinery:
records with a lifecycle, who-may-do-what, an audit trail, and e-signatures. OpenGxP builds that
once (`opengxp/core.py`, ~350 lines) and each module is mostly declarative state machines
(`opengxp/modules.py`). Cross-module links are native, not integrations: an OOS result in LIMS
or an excursion in MES opens a QMS deviation, and the sample/batch cannot be approved/released
until it is closed.

### Part 11 / Annex 11 controls in the kernel

| Requirement | Implementation |
|---|---|
| 11.10(d) limited access, 11.300 credential controls | Unique users, salted PBKDF2-SHA256, lockout after 3 failures |
| 11.10(e) audit trail (who/what/when/why, old values kept) | Every create/update/transition/signature/login failure logged; DB triggers make it append-only; SHA-256 hash chain detects tampering even by a DB admin (`verify_audit_chain`) |
| Annex 11 §9 reason for change | `update()` refuses changes without a reason |
| 11.10(f) operational sequencing | Workflow transitions with source-state checks and guards |
| 11.10(g) authority checks | Role per transition; optional separation of duties (author ≠ approver) |
| 11.50 / 11.70 / 11.200 e-signatures | Password re-entry, printed name, UTC time, meaning; bound to a hash of the signed version (`verify_signatures`) |
| Data integrity (ALCOA+) | Immutable version snapshot per change; optimistic locking against concurrent edits |

## Quick start

```bash
python3 -m unittest discover -s tests -t .      # 11 end-to-end tests, <2 s
python3 -m opengxp.admin opengxp.db create-user qa1 "Q. Approver" qa
python3 -m opengxp.api opengxp.db 8080          # REST API, see opengxp/api.py for routes
```

Python use:

```python
from opengxp import open_system, modules as m
s = open_system("opengxp.db")
```
`tests/test_suite.py` walks every module end-to-end and is the best usage reference.

## Honest gap to commercial suites

This is a working foundation, not a drop-in replacement. Rough order-of-magnitude: each
commercial product is 10⁶+ lines and decades of customer-driven features. What is missing,
roughly in the order a pilot site would hit it:

1. **UI** – only a REST API exists. A web front end is the biggest single gap.
2. **Production deployment** – PostgreSQL backend, TLS, SSO/LDAP, session tokens, backup/restore, HA.
3. **Instrument & equipment integration** – balances, HPLC/CDS (Empower/Chromeleon), OPC-UA/PLC for MES, label printing.
4. **Configurable forms/workflows** – today a new record type means Python code; commercial tools let QA configure it.
5. **Domain depth** – LIMS: stability studies, environmental monitoring, sample plans, reagents/instruments calibration. MES: weigh & dispense, material genealogy/ERP (SAP) interface, equipment status, yield reconciliation. DMS: PDF rendering, watermarks, training records tied to SOP effectivity. QMS: complaints, audits, supplier quality, trending.
6. **Electronic records export** – human-readable + PDF copies for inspectors (11.10(b)).

Unknowns: "Tantra" and "GoVal" from the original request could not be identified with
certainty; `csv` assumes GoVal means a paperless validation lifecycle tool.

## Regulatory note

No software is "Part 11 compliant" or "validated" out of the box: the regulated company validates
it for its intended use (GAMP 5, risk-based). The `csv` module and this test suite are a starting
point for that evidence, and OpenGxP is GAMP Category 4/5 depending on how much you configure or extend it.

Product names above are trademarks of their owners and are used only to describe categories;
OpenGxP is not affiliated with them.

## License

MIT – see `LICENSE`.
