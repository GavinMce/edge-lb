#!/usr/bin/env python3
"""Tiny controller API client for the e2e script. Usage: api.py METHOD PATH [JSON]; prints the response body."""
import http.cookiejar, json, os, sys, urllib.request, urllib.error

BASE = os.environ.get("CTL", "http://127.0.0.1:8080")
JAR = http.cookiejar.MozillaCookieJar("/tmp/api-cookies.txt")
try:
    JAR.load(ignore_discard=True)
except Exception:
    pass
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(JAR))

def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"X-EdgeLB": "1", "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=20) as r:
            JAR.save(ignore_discard=True)
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

if __name__ == "__main__":
    method, path = sys.argv[1], sys.argv[2]
    body = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
    status, text = call(method, path, body)
    print(text)
    sys.exit(0 if status < 300 else 1)
