"""The five application modules. Each is a set of record types on the shared kernel plus
the small amount of domain logic that a state machine cannot express.

  QMS  - deviations, CAPA, change control                 (TrackWise-class)
  DMS  - controlled documents, revisions, supersession    (Documentum D2-class)
  LIMS - specifications, samples, results, OOS            (LabWare-class)
  MES  - master batch records, electronic batch execution (PAS-X-class)
  CSV  - URS, test scripts, execution, traceability       (ValGenesis/Kneat-class)
"""
from .core import GxPError, RecordType, Transition

SYSTEM_USER = {"username": "system", "full_name": "OpenGxP automation", "roles": {"admin"}}

QA = ("qa",)
CLOSED_DEVIATION_STATES = ("closed",)


def open_deviations(system, rid):
    return [d for d in system.linked(rid) if d["rtype"] == "qms.deviation"
            and d["state"] not in CLOSED_DEVIATION_STATES]


def raise_deviation(system, source, title, description, kind):
    """Automatic cross-module escalation: any out-of-limit event opens a QMS deviation."""
    dev = system.create(SYSTEM_USER, "qms.deviation", {
        "title": title, "description": description, "source": source["number"], "category": kind})
    system.link(SYSTEM_USER, source["id"], dev["id"], kind)
    return dev


def _no_open_deviations(system, rec):
    open_ = open_deviations(system, rec["id"])
    if open_:
        return "open deviations must be closed first: " + ", ".join(d["number"] for d in open_)


def _fields(*names):
    def guard(system, rec):
        missing = [n for n in names if not rec["data"].get(n)]
        if missing:
            return "required before this step: " + ", ".join(missing)
    return guard


def _all(*guards):
    def guard(system, rec):
        for g in guards:
            problem = g(system, rec)
            if problem:
                return problem
    return guard


# ======================= QMS =======================
def _capas_closed(system, rec):
    open_ = [c for c in system.linked(rec["id"], "capa") if c["state"] != "closed"]
    if open_:
        return "linked CAPAs must be closed first: " + ", ".join(c["number"] for c in open_)


QMS_TYPES = [
    RecordType("qms", "qms.deviation", "DEV", "open", editable_states=("open", "investigation"),
               required=("title", "description"), transitions=[
        Transition("start_investigation", ("open",), "investigation", ("qa", "author", "analyst", "operator")),
        Transition("submit", ("investigation",), "pending_approval", ("qa", "author", "analyst", "operator"),
                   guard=_fields("root_cause", "impact_assessment")),
        Transition("reject_investigation", ("pending_approval",), "investigation", QA, requires_reason=True),
        Transition("approve_closure", ("pending_approval",), "closed", QA,
                   signature="QA approval of deviation closure", guard=_capas_closed),
    ]),
    RecordType("qms", "qms.capa", "CAPA", "open", editable_states=("open",),
               required=("title", "action_plan"), transitions=[
        Transition("implement", ("open",), "implemented", ("qa", "author", "operator", "analyst"),
                   guard=_fields("action_taken")),
        Transition("verify_effectiveness", ("implemented",), "closed", QA,
                   signature="QA verification of CAPA effectiveness", separation_of_duties=True),
    ]),
    RecordType("qms", "qms.change", "CC", "draft", editable_states=("draft",),
               required=("title", "description", "risk"), transitions=[
        Transition("submit", ("draft",), "submitted", ("author", "qa")),
        Transition("approve", ("submitted",), "approved", QA,
                   signature="QA approval of change", separation_of_duties=True),
        Transition("implement", ("approved",), "implemented", ("author", "qa")),
        Transition("close", ("implemented",), "closed", QA, signature="QA closure of change"),
    ]),
]


def open_capa(system, user, deviation_id, title, action_plan):
    dev = system.get(deviation_id)
    capa = system.create(user, "qms.capa", {"title": title, "action_plan": action_plan,
                                            "deviation": dev["number"]})
    system.link(user, dev["id"], capa["id"], "capa")
    return capa


# ======================= DMS =======================
def _supersede_previous(system, user, rec):
    for old in system.linked(rec["id"], "supersedes"):
        if old["state"] == "effective":
            system.transition(SYSTEM_USER, old["id"], "supersede")


DMS_TYPES = [
    RecordType("dms", "dms.document", "DOC", "draft", editable_states=("draft",),
               required=("title", "doc_code", "content"),
               on_enter={"effective": _supersede_previous}, transitions=[
        Transition("submit_for_review", ("draft",), "in_review", ("author", "qa")),
        Transition("return_to_draft", ("in_review",), "draft", ("qa", "author"), requires_reason=True),
        Transition("approve", ("in_review",), "approved", QA,
                   signature="QA approval of document", separation_of_duties=True),
        Transition("make_effective", ("approved",), "effective", QA),
        Transition("supersede", ("effective",), "superseded", ("admin",)),
        Transition("retire", ("effective",), "obsolete", QA, signature="QA retirement of document",
                   requires_reason=True),
    ]),
]


def revise_document(system, user, doc_id):
    old = system.get(doc_id)
    if old["state"] != "effective":
        raise GxPError("only an effective document can be revised")
    if any(d["state"] not in ("superseded", "obsolete") for d in system.linked(old["id"], "supersedes", reverse=True)):
        raise GxPError("a revision of this document is already in progress")
    data = {**old["data"], "revision": old["data"].get("revision", 1) + 1}
    new = system.create(user, "dms.document", data)
    system.link(user, new["id"], old["id"], "supersedes")
    return new


# ======================= LIMS =======================
def _all_results_entered(system, rec):
    spec = system.get(rec["data"]["spec"])
    missing = [t["test"] for t in spec["data"]["tests"] if t["test"] not in rec["data"].get("results", {})]
    if missing:
        return "results missing for: " + ", ".join(missing)


LIMS_TYPES = [
    RecordType("lims", "lims.spec", "SPEC", "draft", editable_states=("draft",),
               required=("product", "tests"), transitions=[
        Transition("approve", ("draft",), "approved", QA,
                   signature="QA approval of specification", separation_of_duties=True),
        Transition("retire", ("approved",), "retired", QA, requires_reason=True),
    ]),
    RecordType("lims", "lims.sample", "SMP", "registered", required=("spec", "product", "lot"), transitions=[
        Transition("receive", ("registered",), "received", ("analyst", "lab_reviewer")),
        Transition("start_testing", ("received",), "in_testing", ("analyst",)),
        Transition("complete_testing", ("in_testing",), "tested", ("analyst",), guard=_all_results_entered),
        Transition("review", ("tested",), "reviewed", ("lab_reviewer",),
                   signature="Second-person review of results"),
        Transition("approve", ("reviewed",), "approved", QA,
                   signature="QA approval of sample results", guard=_no_open_deviations),
        Transition("reject", ("reviewed",), "rejected", QA, signature="QA rejection of sample",
                   requires_reason=True),
    ]),
]


def register_sample(system, user, spec_id, lot):
    spec = system.get(spec_id)
    if spec["state"] != "approved":
        raise GxPError(f"specification {spec['number']} is not approved")
    return system.create(user, "lims.sample", {"spec": spec["number"], "product": spec["data"]["product"],
                                               "lot": lot, "results": {}})


def evaluate(limit, value):
    lo, hi = limit.get("min"), limit.get("max")
    return (lo is None or value >= lo) and (hi is None or value <= hi)


def enter_result(system, user, sample_id, test, value, reason=None):
    """Record a result, evaluate it against the approved spec, and raise an OOS deviation if it fails."""
    system._require_role(user, ("analyst",))
    sample = system.get(sample_id)
    if sample["state"] != "in_testing":
        raise GxPError(f"{sample['number']} is not in testing")
    limit = next((t for t in system.get(sample["data"]["spec"])["data"]["tests"] if t["test"] == test), None)
    if limit is None:
        raise GxPError(f"test '{test}' is not in the specification")
    results = dict(sample["data"]["results"])
    if test in results and not reason:
        raise GxPError("re-entering a result requires a reason")
    passed = evaluate(limit, value)
    results[test] = {"value": value, "unit": limit.get("unit"), "pass": passed, "analyst": user["username"]}
    sample = system.update(user, sample["id"], {"results": results}, reason, _system=True)
    if not passed:
        raise_deviation(system, sample, f"OOS: {test} on {sample['data']['lot']}",
                        f"{test} = {value} {limit.get('unit', '')} outside "
                        f"[{limit.get('min')}, {limit.get('max')}]", "oos")
    return sample


# ======================= MES =======================
def _all_steps_executed(system, rec):
    missing = [s["id"] for s in rec["data"]["steps"] if s["id"] not in rec["data"]["executions"]]
    if missing:
        return "steps not executed: " + ", ".join(missing)


MES_TYPES = [
    RecordType("mes", "mes.mbr", "MBR", "draft", editable_states=("draft",),
               required=("product", "steps"), transitions=[
        Transition("approve", ("draft",), "approved", QA,
                   signature="QA approval of master batch record", separation_of_duties=True),
        Transition("retire", ("approved",), "retired", QA, requires_reason=True),
    ]),
    RecordType("mes", "mes.batch", "BATCH", "planned", required=("mbr", "lot", "steps"), transitions=[
        Transition("start", ("planned",), "in_progress", ("operator", "production_supervisor")),
        Transition("complete", ("in_progress",), "executed", ("operator", "production_supervisor"),
                   guard=_all_steps_executed),
        Transition("production_review", ("executed",), "reviewed", ("production_supervisor",),
                   signature="Production review of batch record"),
        Transition("release", ("reviewed",), "released", QA,
                   signature="QA batch release", guard=_no_open_deviations),
        Transition("reject", ("reviewed",), "rejected", QA, signature="QA batch rejection", requires_reason=True),
    ]),
]


def create_batch(system, user, mbr_id, lot):
    mbr = system.get(mbr_id)
    if mbr["state"] != "approved":
        raise GxPError(f"master batch record {mbr['number']} is not approved")
    return system.create(user, "mes.batch", {"mbr": mbr["number"], "product": mbr["data"]["product"],
                                             "lot": lot, "steps": mbr["data"]["steps"], "executions": {}})


def record_step(system, user, batch_id, step_id, value=None, password=None):
    """Execute one batch step, signed by the operator; steps must run in master-record order."""
    system._require_role(user, ("operator",))
    batch = system.get(batch_id)
    if batch["state"] != "in_progress":
        raise GxPError(f"{batch['number']} is not in progress")
    steps, done = batch["data"]["steps"], batch["data"]["executions"]
    expected = next((s for s in steps if s["id"] not in done), None)
    if expected is None or expected["id"] != step_id:
        raise GxPError(f"out of sequence: next step is {expected and expected['id']}")
    if "param" in expected and value is None:
        raise GxPError(f"step {step_id} requires a value for {expected['param']}")
    within = value is None or evaluate(expected, value)
    system._reauthenticate(user, password)
    executions = {**done, step_id: {"value": value, "within_limits": within, "by": user["username"]}}
    with system._tx():
        batch = system.update(user, batch["id"], {"executions": executions}, None, _system=True)
        system._record_signature(user, batch, f"Performed step {step_id}")
    if not within:
        raise_deviation(system, batch, f"Process excursion: {expected['param']} at step {step_id}",
                        f"{expected['param']} = {value} {expected.get('unit', '')} outside "
                        f"[{expected.get('min')}, {expected.get('max')}]", "excursion")
    return batch


def review_by_exception(system, batch_id):
    """What a reviewer must look at: only excursions and deviations, not every in-limit step."""
    batch = system.get(batch_id)
    return {"excursions": {k: v for k, v in batch["data"]["executions"].items() if not v["within_limits"]},
            "deviations": [(d["number"], d["state"]) for d in system.linked(batch["id"])
                           if d["rtype"] == "qms.deviation"]}


# ======================= CSV =======================
def traceability(system, system_id):
    """Requirement -> test -> result matrix for one computerised system."""
    target = system.get(system_id)
    tests = [t for t in system.find("csv.test") if t["data"]["system"] == target["number"]]
    matrix = []
    for req in system.find("csv.requirement"):
        if req["data"]["system"] != target["number"] or req["state"] != "approved":
            continue
        covering = [t for t in tests if req["number"] in t["data"]["requirements"]]
        matrix.append({"requirement": req["number"], "ref": req["data"]["ref"], "risk": req["data"]["risk"],
                       "tests": [(t["number"], t["state"]) for t in covering],
                       "verified": any(t["state"] == "passed" for t in covering)})
    return matrix


def _validation_complete(system, rec):
    matrix = traceability(system, rec["id"])
    if not matrix:
        return "no approved requirements"
    gaps = [m["requirement"] for m in matrix if not m["verified"]]
    if gaps:
        return "requirements without a passed test: " + ", ".join(gaps)
    tests = [t for t in system.find("csv.test") if t["data"]["system"] == rec["number"]]
    open_ = [d["number"] for t in tests for d in open_deviations(system, t["id"])]
    if open_:
        return "open test incidents: " + ", ".join(open_)


CSV_TYPES = [
    RecordType("csv", "csv.system", "SYS", "planning", editable_states=("planning",),
               required=("name", "gamp_category", "intended_use"), transitions=[
        Transition("approve_plan", ("planning",), "in_validation", ("validation_lead", "qa"),
                   signature="Approval of validation plan"),
        Transition("release", ("in_validation",), "validated", QA,
                   signature="QA approval of validation summary report", guard=_validation_complete),
        Transition("retire", ("validated",), "retired", QA, signature="QA system retirement",
                   requires_reason=True),
    ]),
    RecordType("csv", "csv.requirement", "URS", "draft", editable_states=("draft",),
               required=("system", "ref", "text", "risk"), transitions=[
        Transition("approve", ("draft",), "approved", ("qa", "validation_lead"),
                   signature="Approval of user requirement", separation_of_duties=True),
    ]),
    RecordType("csv", "csv.test", "TS", "draft", editable_states=("draft",),
               required=("system", "requirements", "steps"), transitions=[
        Transition("approve", ("draft",), "approved", ("qa", "validation_lead"),
                   signature="Pre-execution approval of test script", separation_of_duties=True),
        Transition("pass", ("approved",), "passed", ("tester",), signature="Executed by"),
        Transition("fail", ("approved",), "failed", ("tester",), signature="Executed by"),
        Transition("retest", ("failed",), "approved", ("validation_lead", "qa"),
                   guard=_no_open_deviations, requires_reason=True),
    ]),
]


def execute_test(system, user, test_id, actuals, password):
    """actuals: one observed result per script step. Any mismatch fails the script and opens an incident."""
    system._require_role(user, ("tester",))
    test = system.get(test_id)
    if test["state"] != "approved":
        raise GxPError(f"{test['number']} is not approved for execution")
    steps = test["data"]["steps"]
    if len(actuals) != len(steps):
        raise GxPError(f"expected {len(steps)} step results, got {len(actuals)}")
    system._reauthenticate(user, password)
    run = [{**s, "actual": a, "pass": a == s["expected"]} for s, a in zip(steps, actuals)]
    runs = test["data"].get("runs", []) + [{"by": user["username"], "steps": run}]
    test = system.update(user, test["id"], {"runs": runs}, None, _system=True)
    failed = [r for r in run if not r["pass"]]
    test = system.transition(user, test["id"], "fail" if failed else "pass", password)
    if failed:
        raise_deviation(system, test, f"Test incident in {test['number']}",
                        "; ".join(f"{r['action']}: expected {r['expected']!r}, got {r['actual']!r}"
                                  for r in failed), "test_incident")
    return test


def install(system):
    for rt in QMS_TYPES + DMS_TYPES + LIMS_TYPES + MES_TYPES + CSV_TYPES:
        system.register(rt)
