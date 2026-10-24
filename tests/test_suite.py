import sqlite3
import unittest

from opengxp import GxPError, core, open_system
from opengxp import modules as m

core.PBKDF2_ROUNDS = 1_000  # keep the suite fast; production uses the default
PW = "Correct-Horse-9"


def setup_system():
    s = open_system()
    for name, roles in [("ana", ["analyst"]), ("rev", ["lab_reviewer"]), ("qa1", ["qa"]), ("qa2", ["qa"]),
                        ("auth", ["author"]), ("op", ["operator"]), ("sup", ["production_supervisor"]),
                        ("val", ["validation_lead"]), ("tst", ["tester"])]:
        s.create_user(name, name.upper(), roles, PW)
    return s, {u: s.user(u) for u in ["ana", "rev", "qa1", "qa2", "auth", "op", "sup", "val", "tst"]}


class KernelTests(unittest.TestCase):
    def setUp(self):
        self.s, self.u = setup_system()

    def test_audit_trail_is_append_only_and_chained(self):
        self.s.create(self.u["auth"], "dms.document", {"title": "T", "doc_code": "SOP-1", "content": "x"})
        self.assertEqual(self.s.verify_audit_chain(), (True, None))
        with self.assertRaises(sqlite3.IntegrityError):
            self.s.db.execute("UPDATE audit_trail SET username='mallory'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.s.db.execute("DELETE FROM audit_trail")
        # Bypass the trigger as a privileged attacker would; the hash chain still exposes it.
        self.s.db.execute("DROP TRIGGER audit_trail_no_update")
        self.s.db.execute("UPDATE audit_trail SET username='mallory' WHERE seq=2")
        self.assertEqual(self.s.verify_audit_chain(), (False, 2))

    def test_lockout_after_failed_logins(self):
        for _ in range(3):
            with self.assertRaises(GxPError):
                self.s.authenticate("ana", "wrong-password")
        with self.assertRaisesRegex(GxPError, "locked"):
            self.s.authenticate("ana", PW)

    def test_esig_requires_password_and_separation_of_duties(self):
        doc = self.s.create(self.u["qa1"], "dms.document", {"title": "T", "doc_code": "SOP-1", "content": "x"})
        self.s.transition(self.u["qa1"], doc["id"], "submit_for_review")
        with self.assertRaisesRegex(GxPError, "separation of duties"):
            self.s.transition(self.u["qa1"], doc["id"], "approve", PW)
        with self.assertRaisesRegex(GxPError, "password"):
            self.s.transition(self.u["qa2"], doc["id"], "approve")
        with self.assertRaisesRegex(GxPError, "invalid"):
            self.s.transition(self.u["qa2"], doc["id"], "approve", "nope-nope")
        doc = self.s.transition(self.u["qa2"], doc["id"], "approve", PW)
        self.assertEqual(doc["state"], "approved")
        self.assertTrue(self.s.verify_signatures(doc["id"]))

    def test_changes_need_reason_and_keep_history(self):
        doc = self.s.create(self.u["auth"], "dms.document", {"title": "T", "doc_code": "SOP-1", "content": "v1"})
        with self.assertRaisesRegex(GxPError, "reason"):
            self.s.update(self.u["auth"], doc["id"], {"content": "v2"}, None)
        self.s.update(self.u["auth"], doc["id"], {"content": "v2"}, "typo")
        self.assertEqual([v["data"]["content"] for v in self.s.versions(doc["id"])], ["v1", "v2"])
        self.s.transition(self.u["auth"], doc["id"], "submit_for_review")
        with self.assertRaisesRegex(GxPError, "not editable"):
            self.s.update(self.u["auth"], doc["id"], {"content": "v3"}, "sneaky")

    def test_role_enforcement(self):
        spec = self.s.create(self.u["auth"], "lims.spec", {"product": "P", "tests": [{"test": "a"}]})
        with self.assertRaisesRegex(GxPError, "lacks role"):
            self.s.transition(self.u["ana"], spec["id"], "approve", PW)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.s, self.u = setup_system()

    def close_deviation(self, dev_id):
        s, u = self.s, self.u
        s.transition(u["qa1"], dev_id, "start_investigation")
        s.update(u["qa1"], dev_id, {"root_cause": "probe drift", "impact_assessment": "none"}, "investigation")
        s.transition(u["qa1"], dev_id, "submit")
        capa = m.open_capa(s, u["qa1"], dev_id, "Recalibrate", "calibrate monthly")
        with self.assertRaisesRegex(GxPError, "CAPA"):
            s.transition(u["qa2"], dev_id, "approve_closure", PW)
        s.update(u["qa1"], capa["id"], {"action_taken": "done"}, "implemented")
        s.transition(u["qa1"], capa["id"], "implement")
        s.transition(u["qa2"], capa["id"], "verify_effectiveness", PW)
        s.transition(u["qa2"], dev_id, "approve_closure", PW)

    def test_dms_revision_supersedes_previous(self):
        s, u = self.s, self.u
        doc = s.create(u["auth"], "dms.document", {"title": "Cleaning", "doc_code": "SOP-7", "content": "a"})
        for t, who in [("submit_for_review", "auth"), ("approve", "qa1"), ("make_effective", "qa1")]:
            s.transition(u[who], doc["id"], t, PW)
        rev = m.revise_document(s, u["auth"], doc["id"])
        self.assertEqual(rev["data"]["revision"], 2)
        for t, who in [("submit_for_review", "auth"), ("approve", "qa1"), ("make_effective", "qa1")]:
            s.transition(u[who], rev["id"], t, PW)
        self.assertEqual(s.get(doc["id"])["state"], "superseded")
        self.assertEqual(s.get(rev["id"])["state"], "effective")

    def test_lims_oos_blocks_approval_until_deviation_closed(self):
        s, u = self.s, self.u
        spec = s.create(u["auth"], "lims.spec", {"product": "Aspirin 100mg", "tests": [
            {"test": "assay", "min": 95.0, "max": 105.0, "unit": "%"},
            {"test": "water", "max": 0.5, "unit": "%"}]})
        s.transition(u["qa1"], spec["id"], "approve", PW)
        smp = m.register_sample(s, u["ana"], spec["id"], "LOT-1")
        s.transition(u["ana"], smp["id"], "receive")
        s.transition(u["ana"], smp["id"], "start_testing")
        m.enter_result(s, u["ana"], smp["id"], "assay", 99.2)
        with self.assertRaisesRegex(GxPError, "results missing"):
            s.transition(u["ana"], smp["id"], "complete_testing")
        m.enter_result(s, u["ana"], smp["id"], "water", 0.9)  # OOS
        devs = m.open_deviations(s, smp["id"])
        self.assertEqual(len(devs), 1)
        s.transition(u["ana"], smp["id"], "complete_testing")
        s.transition(u["rev"], smp["id"], "review", PW)
        with self.assertRaisesRegex(GxPError, "open deviations"):
            s.transition(u["qa1"], smp["id"], "approve", PW)
        self.close_deviation(devs[0]["id"])
        self.assertEqual(s.transition(u["qa1"], smp["id"], "approve", PW)["state"], "approved")

    def test_mes_batch_execution_and_release(self):
        s, u = self.s, self.u
        mbr = s.create(u["auth"], "mes.mbr", {"product": "Aspirin 100mg", "steps": [
            {"id": "10", "instruction": "Dispense API"},
            {"id": "20", "instruction": "Granulate", "param": "temp", "min": 40, "max": 50, "unit": "C"},
            {"id": "30", "instruction": "Compress", "param": "hardness", "min": 8, "max": 12, "unit": "kp"}]})
        with self.assertRaisesRegex(GxPError, "not approved"):
            m.create_batch(s, u["sup"], mbr["id"], "B1")
        s.transition(u["qa1"], mbr["id"], "approve", PW)
        b = m.create_batch(s, u["sup"], mbr["id"], "B1")
        s.transition(u["op"], b["id"], "start")
        with self.assertRaisesRegex(GxPError, "out of sequence"):
            m.record_step(s, u["op"], b["id"], "20", 45, PW)
        m.record_step(s, u["op"], b["id"], "10", None, PW)
        m.record_step(s, u["op"], b["id"], "20", 55, PW)  # excursion
        m.record_step(s, u["op"], b["id"], "30", 10, PW)
        s.transition(u["op"], b["id"], "complete")
        s.transition(u["sup"], b["id"], "production_review", PW)
        rbe = m.review_by_exception(s, b["id"])
        self.assertEqual(list(rbe["excursions"]), ["20"])
        with self.assertRaisesRegex(GxPError, "open deviations"):
            s.transition(u["qa1"], b["id"], "release", PW)
        self.close_deviation(m.open_deviations(s, b["id"])[0]["id"])
        self.assertEqual(s.transition(u["qa1"], b["id"], "release", PW)["state"], "released")
        self.assertTrue(s.verify_signatures(b["id"]))
        self.assertEqual(len(s.signatures(b["id"])), 5)

    def test_csv_traceability_gates_release(self):
        s, u = self.s, self.u
        sysrec = s.create(u["val"], "csv.system", {"name": "OpenGxP", "gamp_category": 4,
                                                   "intended_use": "QC release"})
        s.transition(u["val"], sysrec["id"], "approve_plan", PW)
        r1 = s.create(u["val"], "csv.requirement", {"system": sysrec["number"], "ref": "URS-1",
                                                    "text": "Audit trail", "risk": "high"})
        r2 = s.create(u["val"], "csv.requirement", {"system": sysrec["number"], "ref": "URS-2",
                                                    "text": "E-signature", "risk": "high"})
        for r in (r1, r2):
            s.transition(u["qa1"], r["id"], "approve", PW)
        t1 = s.create(u["val"], "csv.test", {"system": sysrec["number"], "requirements": [r1["number"]],
                                             "steps": [{"action": "edit record", "expected": "audited"}]})
        s.transition(u["qa1"], t1["id"], "approve", PW)
        with self.assertRaisesRegex(GxPError, "without a passed test"):
            s.transition(u["qa1"], sysrec["id"], "release", PW)
        t2 = s.create(u["val"], "csv.test", {"system": sysrec["number"], "requirements": [r2["number"]],
                                             "steps": [{"action": "sign", "expected": "manifested"}]})
        s.transition(u["qa1"], t2["id"], "approve", PW)
        m.execute_test(s, u["tst"], t1["id"], ["audited"], PW)
        m.execute_test(s, u["tst"], t2["id"], ["nothing shown"], PW)  # fails -> incident
        self.assertEqual(s.get(t2["id"])["state"], "failed")
        inc = m.open_deviations(s, t2["id"])[0]
        self.close_deviation(inc["id"])
        s.transition(u["val"], t2["id"], "retest", reason="fix deployed")
        m.execute_test(s, u["tst"], t2["id"], ["manifested"], PW)
        self.assertTrue(all(row["verified"] for row in m.traceability(s, sysrec["id"])))
        self.assertEqual(s.transition(u["qa1"], sysrec["id"], "release", PW)["state"], "validated")
        self.assertEqual(s.verify_audit_chain(), (True, None))


if __name__ == "__main__":
    unittest.main()
