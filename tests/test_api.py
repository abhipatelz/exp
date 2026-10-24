import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from opengxp import core, open_system
from opengxp.api import make_handler

core.PBKDF2_ROUNDS = 1_000
PW = "Correct-Horse-9"


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.system = open_system()
        cls.system.create_user("auth", "Author", ["author"], PW)
        cls.system.create_user("qa", "QA", ["qa"], PW)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.system))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def call(self, method, path, body=None, user="auth"):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-User": user, "X-Password": PW})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_document_lifecycle_over_http(self):
        status, doc = self.call("POST", "/records", {"type": "dms.document",
                                                     "data": {"title": "T", "doc_code": "SOP-9", "content": "c"}})
        self.assertEqual(status, 200)
        self.call("POST", f"/records/{doc['number']}/transition", {"name": "submit_for_review"})
        status, err = self.call("POST", f"/records/{doc['number']}/transition", {"name": "approve"}, user="qa")
        self.assertEqual((status, err["error"]), (422, "electronic signature requires password re-entry"))
        status, doc = self.call("POST", f"/records/{doc['number']}/transition",
                                {"name": "approve", "password": PW}, user="qa")
        self.assertEqual(doc["state"], "approved")
        _, audit = self.call("GET", f"/records/{doc['number']}/audit")
        self.assertIn("esign", [a["action"] for a in audit])
        self.assertEqual(self.call("GET", "/audit/verify")[1], {"intact": True, "first_bad_seq": None})

    def test_rejects_bad_credentials(self):
        req = urllib.request.Request(self.base + "/types", headers={"X-User": "qa", "X-Password": "bad"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
