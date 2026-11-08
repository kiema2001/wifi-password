import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPCookieProcessor, build_opener, Request

ROUTER = "http://192.168.1.1"
API = ROUTER + "/cgi-bin/luci/admin/routerweb"
session = {"opener": None}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.environ.get("WIFI_DASHBOARD_DIR", BASE_DIR)
ROUTER = os.environ.get("WIFI_ROUTER_URL", ROUTER).rstrip("/")
API = ROUTER + "/cgi-bin/luci/admin/routerweb"
STATE_FILE = os.environ.get("WIFI_POLICY_FILE", os.path.join(BASE_DIR, "wifi-policy.json"))
state_lock = threading.Lock()

if os.path.exists(STATE_FILE):
    with open(STATE_FILE, "r", encoding="utf-8") as handle:
        policy_state = json.load(handle)
else:
    policy_state = {"schedules": [], "manualBlocks": []}
policy_state.setdefault("credits", [])
policy_state.setdefault("manualBlocks", [])


def save_state():
    with open(STATE_FILE, "w", encoding="utf-8") as handle:
        json.dump(policy_state, handle, ensure_ascii=True)


def in_schedule(schedule):
    if not schedule.get("enabled"):
        return False
    now = datetime.now().strftime("%H:%M")
    return schedule["start"] <= now <= schedule["end"]


def apply_access_credits():
    if session["opener"] is None:
        return
    try:
        changed = False
        blacklist = router_request("/deny_dev_list")
        blocked_macs = {
            str(item.get("mac", "") if isinstance(item, dict) else item).lower()
            for item in blacklist.get("list", [])
            if str(item.get("mac", "") if isinstance(item, dict) else item)
        }
        for credit in policy_state.get("credits", []):
            if not credit.get("mac"):
                continue
            deadline = datetime.fromisoformat(credit["expiresAt"].replace("Z", "+00:00"))
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            deadline = deadline.astimezone(timezone.utc)
            now = datetime.now(timezone.utc)
            should_block = now >= deadline
            mac = credit["mac"].lower()
            currently_blocked = mac in blocked_macs
            if currently_blocked != should_block:
                result = router_request("/deny_dev", "POST", {
                    "mac": mac,
                    "disabled": 1 if should_block else 0
                })
                if isinstance(result, dict) and result.get("result", 0) == 0:
                    credit["blocked"] = should_block
                    changed = True
                    if should_block:
                        blocked_macs.add(mac)
                    else:
                        blocked_macs.discard(mac)
        if changed:
            save_state()
    except Exception:
        return


def apply_schedules():
    if session["opener"] is None:
        return
    try:
        change_ids = []
        for schedule in policy_state.get("schedules", []):
            should_block = not in_schedule(schedule)
            if schedule.get("mac") and should_block != schedule.get("blocked", False):
                router_request("/deny_dev", "POST", {
                    "mac": schedule["mac"],
                    "disabled": 1 if should_block else 0
                })
                schedule["blocked"] = should_block
                change_ids.append(schedule["id"])
        if change_ids:
            save_state()
    except Exception:
        return


def schedule_worker():
    while True:
        apply_schedules()
        apply_access_credits()
        time.sleep(15)


def send_json(handler, status, data):
    body = json.dumps(data).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def router_request(path, method="GET", payload=None):
    opener = session["opener"]
    if opener is None:
        raise RuntimeError("Router is not logged in")
    url = path if urlparse(path).scheme else API + path
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read()
            text = raw.decode("utf-8", errors="replace")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text, "contentType": response.headers.get("Content-Type", "")}
    except HTTPError as error:
        raise RuntimeError("Router returned HTTP %s" % error.code)
    except URLError as error:
        raise RuntimeError("Router is unreachable: %s" % error.reason)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_POST(self):
        if self.path == "/api/login":
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            password = request.get("password", "")
            if not password:
                send_json(self, 400, {"result": 1, "error": "Password is required"})
                return
            opener = build_opener(HTTPCookieProcessor(CookieJar()))
            try:
                data = json.dumps({"username": "CMCCAdmin", "password": password}).encode("utf-8")
                req = Request(API + "/login", data=data, headers={"Content-Type": "application/json"}, method="POST")
                with opener.open(req, timeout=15) as response:
                    result = json.loads(response.read().decode("utf-8"))
                if result.get("result") != 0:
                    send_json(self, 401, {"result": 1, "error": "Router rejected the password"})
                    return
                session["opener"] = opener
                send_json(self, 200, {"result": 0})
            except Exception as error:
                send_json(self, 502, {"result": 1, "error": str(error)})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else None
            if self.path == "/api/block":
                result = router_request("/deny_dev", "POST", payload)
                if isinstance(result, dict) and result.get("result", 0) == 0 and payload.get("mac"):
                    mac = payload["mac"].lower()
                    with state_lock:
                        policy_state["manualBlocks"] = [
                            item for item in policy_state["manualBlocks"]
                            if item.get("mac", "").lower() != mac
                        ]
                        if payload.get("disabled") == 1:
                            policy_state["manualBlocks"].append({
                                "name": payload.get("name", mac),
                                "ip": payload.get("ip", ""),
                                "mac": mac
                            })
                        save_state()
            elif self.path == "/api/firewall":
                result = router_request("/firewall_rule_apply", "POST", payload)
            elif self.path in ("/api/schedules", "/api/block-ip"):
                if self.path == "/api/schedules":
                    with state_lock:
                        policy_state["schedules"] = payload.get("schedules", [])
                        save_state()
                    result = {"result": 0}
                else:
                    identity = payload.get("ip") or payload.get("mac")
                    mac = payload.get("mac", "")
                    if payload.get("method") == "ip" and payload.get("ip"):
                        devices = router_request("/associated_devs")
                        match = next((d for d in devices.get("list", []) if d.get("ip") == payload["ip"]), None)
                        mac = match.get("mac", "") if match else ""
                    if not mac:
                        raise RuntimeError("The device MAC could not be resolved. Use the MAC block button for this device.")
                    result = router_request("/deny_dev", "POST", {
                        "mac": mac,
                        "disabled": 1 if payload.get("blocked") else 0
                    })
            elif self.path == "/api/credits":
                with state_lock:
                    policy_state["credits"] = payload.get("credits", [])
                    save_state()
                result = {"result": 0}
                apply_access_credits()
            else:
                send_json(self, 404, {"error": "Unknown API"})
                return
            send_json(self, 200, result)
        except Exception as error:
            send_json(self, 502, {"error": str(error)})

    def do_GET(self):
        if self.path == "/api/status":
            send_json(self, 200, {"loggedIn": session["opener"] is not None})
            return
        if self.path in ("/api/devices", "/api/blacklist", "/api/firewall"):
            endpoint = {
                "/api/devices": "/associated_devs",
                "/api/blacklist": "/deny_dev_list",
                "/api/firewall": "/firewall_rule",
            }[self.path]
            try:
                send_json(self, 200, router_request(endpoint))
            except Exception as error:
                send_json(self, 502, {"error": str(error)})
            return
        if self.path == "/api/schedules":
            send_json(self, 200, policy_state)
            return
        if self.path == "/api/credits":
            send_json(self, 200, policy_state)
            return
        if self.path == "/api/managed":
            try:
                blocked = router_request("/deny_dev_list").get("list", [])
                existing = {item.get("mac", "").lower() for item in policy_state["manualBlocks"]}
                for item in blocked:
                    mac = str(item.get("mac", "")).lower()
                    if mac and mac not in existing:
                        policy_state["manualBlocks"].append({
                            "name": item.get("hostname") or mac,
                            "ip": "",
                            "mac": mac
                        })
                        existing.add(mac)
                send_json(self, 200, policy_state)
            except Exception as error:
                send_json(self, 502, {"error": str(error)})
            return
        super().do_GET()


if __name__ == "__main__":
    threading.Thread(target=schedule_worker, daemon=True).start()
    port = int(os.environ.get("WIFI_DASHBOARD_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
