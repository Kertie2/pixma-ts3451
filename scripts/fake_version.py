# fake_version.py
from mitmproxy import http

class FakeCanonVersion:
    def response(self, flow: http.HTTPFlow):
        if "dtv-p.c-ij.com" in flow.request.pretty_host and "version.bin" in flow.request.path:
            print(f"[INTERCEPT] version.bin → 0xFF 0xFF")
            flow.response.content = bytes([0xFF, 0xFF])
            flow.response.headers["Content-Length"] = "2"

        # Sauvegarder TOUT ce qui vient de Canon (plus de seuil)
        if any(d in flow.request.pretty_host for d in ["gdlp01.c-wss.com", "c-ij.com"]):
            fname = flow.request.path.split("/")[-1] or "index"
            fpath = f"/tmp/canon_{fname}"
            with open(fpath, "wb") as f:
                f.write(flow.response.content)
            print(f"[SAVED] {flow.request.url} → {fpath} ({len(flow.response.content)}b)")

addons = [FakeCanonVersion()]
