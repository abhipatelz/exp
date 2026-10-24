"""Minimal JSON REST API over the kernel (stdlib only).

Every request authenticates with X-User / X-Password headers. This is a reference
interface for integration and testing; production needs TLS, sessions/SSO and a
WSGI/ASGI server in front.

  GET  /types                                  registered record types
  GET  /records?type=lims.sample&state=...     list records
  GET  /records/{id|number}                    record + available transitions + signatures
  GET  /records/{id}/audit                     audit trail for one record
  GET  /records/{id}/versions                  full version history
  POST /records                {type, data}    create
  POST /records/{id}/update    {changes, reason}
  POST /records/{id}/transition {name, password?, reason?}
  POST /lims/samples           {spec, lot}
  POST /lims/samples/{id}/results {test, value, reason?}
  POST /mes/batches            {mbr, lot}
  POST /mes/batches/{id}/steps {step, value?, password}
  GET  /mes/batches/{id}/review
  POST /csv/tests/{id}/execute {actuals, password}
  GET  /csv/systems/{id}/trace
  GET  /audit/verify
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import modules as m
from . import open_system
from .core import GxPError


def make_handler(system):
    def routes(user, method, parts, query, body):
        rec = lambda: system.get(parts[1])  # noqa: E731
        match method, parts:
            case "GET", ["types"]:
                return sorted(system.types)
            case "GET", ["records"]:
                return system.find(query.get("type"), query.get("state"))
            case "GET", ["records", _]:
                r = rec()
                return {**r, "transitions": system.available_transitions(r["id"]),
                        "signatures": system.signatures(r["id"])}
            case "GET", ["records", _, "audit"]:
                return system.audit(rec()["id"])
            case "GET", ["records", _, "versions"]:
                return system.versions(rec()["id"])
            case "POST", ["records"]:
                return system.create(user, body["type"], body["data"])
            case "POST", ["records", _, "update"]:
                return system.update(user, rec()["id"], body["changes"], body.get("reason"))
            case "POST", ["records", _, "transition"]:
                return system.transition(user, rec()["id"], body["name"], body.get("password"), body.get("reason"))
            case "POST", ["lims", "samples"]:
                return m.register_sample(system, user, body["spec"], body["lot"])
            case "POST", ["lims", "samples", sid, "results"]:
                return m.enter_result(system, user, sid, body["test"], body["value"], body.get("reason"))
            case "POST", ["mes", "batches"]:
                return m.create_batch(system, user, body["mbr"], body["lot"])
            case "POST", ["mes", "batches", bid, "steps"]:
                return m.record_step(system, user, bid, body["step"], body.get("value"), body.get("password"))
            case "GET", ["mes", "batches", bid, "review"]:
                return m.review_by_exception(system, bid)
            case "POST", ["csv", "tests", tid, "execute"]:
                return m.execute_test(system, user, tid, body["actuals"], body.get("password"))
            case "GET", ["csv", "systems", sid, "trace"]:
                return m.traceability(system, sid)
            case "GET", ["audit", "verify"]:
                ok, bad = system.verify_audit_chain()
                return {"intact": ok, "first_bad_seq": bad}
        raise LookupError("not found")

    class Handler(BaseHTTPRequestHandler):
        def _serve(self, method):
            url = urlparse(self.path)
            try:
                user = system.authenticate(self.headers.get("X-User", ""), self.headers.get("X-Password", ""))
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else {}
                query = {k: v[0] for k, v in parse_qs(url.query).items()}
                status, payload = 200, routes(user, method, [p for p in url.path.split("/") if p], query, body)
            except GxPError as e:
                status, payload = (401 if "credential" in str(e) or "locked" in str(e) else 422), {"error": str(e)}
            except LookupError as e:
                status, payload = 404, {"error": str(e)}
            except (KeyError, ValueError) as e:
                status, payload = 400, {"error": f"bad request: {e}"}
            data = json.dumps(payload, default=list).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._serve("GET")

        def do_POST(self):
            self._serve("POST")

    return Handler


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else "opengxp.db"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    system = open_system(db)
    if not system.db.execute("SELECT 1 FROM users").fetchone():
        print("No users yet. Create an admin first:\n"
              f"  python -m opengxp.admin {db} create-user admin 'Administrator' admin")
    print(f"OpenGxP API on http://127.0.0.1:{port}  (db: {db})")
    ThreadingHTTPServer(("127.0.0.1", port), make_handler(system)).serve_forever()


if __name__ == "__main__":
    main()
