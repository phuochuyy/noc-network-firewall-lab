"""OPNsense web session (form login + CSRF token), for the legacy restore page and the JSON API.

The GUI itself calls the API with the session cookie and an X-CSRFToken header; scripts do the same, so no
API key has to be stored. Password from ../lab.env (OPN_ROOT_PASSWORD). The GUI certificate is self-signed:
TLS verification is off for this lab address only.
"""
import http.cookiejar
import json
import pathlib
import re
import ssl
import urllib.parse
import urllib.request
import uuid

ENV = pathlib.Path(__file__).resolve().parent.parent / "lab.env"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def env():
    out = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class OPN:
    def __init__(self, host="10.90.10.1"):
        self.base = f"https://{host}"
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                              urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def _get(self, path):
        with self.op.open(self.base + path, timeout=30) as r:
            return r.read().decode(errors="replace")

    def _form_token(self, html):
        m = re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)"', html)
        return m.group(1), m.group(2)

    def login(self, user="root", password=None):
        password = password if password is not None else env()["OPN_ROOT_PASSWORD"]
        k, v = self._form_token(self._get("/"))
        data = urllib.parse.urlencode({k: v, "usernamefld": user, "passwordfld": password, "login": "1"}).encode()
        with self.op.open(self.base + "/", data, timeout=30) as r:
            page = r.read().decode(errors="replace")
        if "passwordfld" in page:
            raise RuntimeError("login failed")
        m = re.search(r'"X-CSRFToken", "([^"]+)"', self._get("/ui/core/dashboard"))
        self.csrf = m.group(1) if m else v
        return self

    def api(self, path, payload=None):
        req = urllib.request.Request(self.base + "/api/" + path.lstrip("/"),
                                     data=None if payload is None else json.dumps(payload).encode(),
                                     headers={"X-CSRFToken": self.csrf, "Content-Type": "application/json"})
        with self.op.open(req, timeout=120) as r:
            body = r.read().decode(errors="replace")
        return json.loads(body) if body.strip().startswith(("{", "[")) else body

    def restore(self, xml_path):
        """Legacy Diagnostics > Backup: restore all areas and reboot."""
        html = self._get("/diag_backup.php")
        k, v = self._form_token(html)
        b = uuid.uuid4().hex
        content = pathlib.Path(xml_path).read_bytes()
        parts = []
        for name, value in [(k, v), ("rebootafterrestore", "on"), ("keepconsole", "on"),
                            ("restore", "Restore configuration")]:
            parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="conffile"; filename="config.xml"\r\n'
                     f'Content-Type: text/xml\r\n\r\n'.encode() + content + b"\r\n")
        parts.append(f"--{b}--\r\n".encode())
        req = urllib.request.Request(self.base + "/diag_backup.php", b"".join(parts),
                                     {"Content-Type": f"multipart/form-data; boundary={b}"})
        with self.op.open(req, timeout=60) as r:
            page = r.read().decode(errors="replace")
        ok = re.search(r"configuration (area )?has been restored|rebooting", page, re.I)
        err = re.search(r'alert-danger[^>]*>([^<]+)', page)
        return bool(ok), (err.group(1).strip() if err else "")
