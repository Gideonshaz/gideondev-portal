"""Minimal client for TikTok for Business' hosted MCP server (stdlib only).

Auth follows the MCP HTTP-transport OAuth spec, which TikTok's API reference lists
for /open_mcp/{server}/: protected-resource discovery, dynamic client registration,
authorization code + PKCE (S256), and refresh. TikTok ends a sign-in 30 days after
authorization, after which Gideon must click Authorize again.

Nothing in this module changes a campaign. Writes live in tiktok_ops.py behind the
safety gate.
"""
import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MCP_URL = "https://business-api.tiktok.com/open_mcp/tt-ads-mcp-flat"
SCOPE = "mcp:tt4b"
TIMEOUT = 30
PROTOCOL_VERSION = "2025-06-18"


class McpError(Exception):
    pass


class AuthError(McpError):
    """Token missing, expired or revoked: Gideon must re-authorize."""


def _http(method, url, data=None, headers=None, form=False):
    headers = dict(headers or {})
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise McpError(f"Network error contacting {urllib.parse.urlsplit(url).netloc}: {e}") from e


def _json(text, what):
    try:
        return json.loads(text)
    except ValueError as e:
        raise McpError(f"{what}: response was not JSON") from e


# ------------------------------------------------------------------ OAuth
def pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def discover(mcp_url=DEFAULT_MCP_URL, http=_http):
    """Return the authorization-server metadata for the MCP server."""
    parts = urllib.parse.urlsplit(mcp_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    prm_url = f"{origin}/.well-known/oauth-protected-resource{parts.path.rstrip('/')}"
    status, _, text = http("GET", prm_url)
    if status != 200:
        raise McpError(f"Protected-resource metadata returned HTTP {status}")
    prm = _json(text, "Protected-resource metadata")
    servers = prm.get("authorization_servers") or []
    if not servers:
        raise McpError("MCP server lists no authorization server")
    issuer = servers[0].rstrip("/")
    candidates = [f"{issuer}/.well-known/oauth-authorization-server",
                  f"{issuer}/.well-known/openid-configuration"]
    ip = urllib.parse.urlsplit(issuer)
    candidates.append(f"{ip.scheme}://{ip.netloc}/.well-known/oauth-authorization-server{ip.path}")
    for url in candidates:
        status, _, text = http("GET", url)
        if status == 200:
            meta = _json(text, "Authorization-server metadata")
            for key in ("authorization_endpoint", "token_endpoint"):
                if not meta.get(key):
                    raise McpError(f"Authorization-server metadata has no {key}")
            if "S256" not in (meta.get("code_challenge_methods_supported") or ["S256"]):
                raise McpError("Authorization server does not support PKCE S256")
            meta["resource"] = prm.get("resource") or mcp_url
            meta["scopes"] = prm.get("scopes_supported") or [SCOPE]
            return meta
    raise McpError("Could not find authorization-server metadata")


def register_client(meta, redirect_uri, http=_http):
    endpoint = meta.get("registration_endpoint")
    if not endpoint:
        raise McpError("Authorization server does not offer dynamic client registration")
    status, _, text = http("POST", endpoint, {
        "client_name": "GideonDev Affiliate LIVE Scheduler",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": " ".join(meta.get("scopes") or [SCOPE]),
    })
    if status not in (200, 201):
        raise McpError(f"Client registration failed (HTTP {status})")
    reg = _json(text, "Client registration")
    if not reg.get("client_id"):
        raise McpError("Client registration returned no client_id")
    return reg


def authorize_url(meta, client_id, redirect_uri, state, challenge):
    q = {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        "scope": " ".join(meta.get("scopes") or [SCOPE]), "resource": meta["resource"],
    }
    sep = "&" if "?" in meta["authorization_endpoint"] else "?"
    return meta["authorization_endpoint"] + sep + urllib.parse.urlencode(q)


def _token_request(token_endpoint, data, client_secret=None, http=_http):
    if client_secret:
        data["client_secret"] = client_secret
    status, _, text = http("POST", token_endpoint, data, form=True)
    try:
        body = json.loads(text)
    except ValueError:
        body = {}
    # Some TikTok endpoints wrap results as {"code":0,"data":{...}}
    if isinstance(body.get("data"), dict) and "access_token" in body["data"]:
        body = body["data"]
    if status in (400, 401) or body.get("error") in ("invalid_grant", "invalid_client"):
        raise AuthError(f"Token endpoint rejected the request ({body.get('error') or status})")
    if status != 200 or not body.get("access_token"):
        raise McpError(f"Token endpoint returned HTTP {status} without an access token")
    return body


def exchange_code(meta_or_endpoint, client_id, code, redirect_uri, verifier, resource,
                  client_secret=None, http=_http):
    endpoint = meta_or_endpoint if isinstance(meta_or_endpoint, str) else meta_or_endpoint["token_endpoint"]
    return _token_request(endpoint, {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": client_id, "code_verifier": verifier, "resource": resource,
    }, client_secret, http)


def refresh(token_endpoint, client_id, refresh_token, resource, client_secret=None, http=_http):
    return _token_request(token_endpoint, {
        "grant_type": "refresh_token", "refresh_token": refresh_token,
        "client_id": client_id, "resource": resource,
    }, client_secret, http)


# ------------------------------------------------------------------ MCP JSON-RPC
class McpSession:
    def __init__(self, url, access_token, http=_http):
        self.url, self.token, self.http = url, access_token, http
        self.session_id = None
        self._id = 0

    def _post(self, payload, expect_reply=True):
        headers = {"Authorization": f"Bearer {self.token}",
                   "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": PROTOCOL_VERSION}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        status, resp_headers, text = self.http("POST", self.url, payload, headers)
        if status in (401, 403):
            raise AuthError(f"MCP server refused the token (HTTP {status})")
        if status >= 400:
            raise McpError(f"MCP server returned HTTP {status}")
        sid = {k.lower(): v for k, v in resp_headers.items()}.get("mcp-session-id")
        if sid:
            self.session_id = sid
        if not expect_reply:
            return None
        return self._parse(text, payload.get("id"))

    @staticmethod
    def _parse(text, want_id):
        messages = []
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            obj = json.loads(stripped)
            messages = obj if isinstance(obj, list) else [obj]
        else:  # Server-Sent Events
            buf = []
            for line in text.splitlines() + [""]:
                if line.startswith("data:"):
                    buf.append(line[5:].lstrip())
                elif not line.strip() and buf:
                    try:
                        messages.append(json.loads("\n".join(buf)))
                    except ValueError:
                        pass
                    buf = []
        for m in messages:
            if isinstance(m, dict) and m.get("id") == want_id:
                if "error" in m:
                    raise McpError(f"MCP error: {m['error'].get('message', m['error'])}")
                return m.get("result")
        raise McpError("MCP server sent no reply for the request")

    def call(self, method, params=None):
        self._id += 1
        return self._post({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})

    def initialize(self):
        result = self.call("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                          "clientInfo": {"name": "gideondev-affiliate-scheduler",
                                                         "version": "1.0"}})
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_reply=False)
        return result

    def list_tools(self, wanted=None):
        tools, cursor = {}, None
        for _ in range(50):
            res = self.call("tools/list", {"cursor": cursor} if cursor else {}) or {}
            for t in res.get("tools", []):
                tools[t["name"]] = t
            cursor = res.get("nextCursor")
            if not cursor or (wanted and all(w in tools for w in wanted)):
                break
        return tools

    def call_tool(self, name, arguments):
        res = self.call("tools/call", {"name": name, "arguments": arguments}) or {}
        if res.get("isError"):
            raise McpError(f"{name} failed: {tool_text(res)[:300]}")
        return res


def tool_text(result):
    return " ".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def tool_payload(result):
    """Best-effort structured payload from a tools/call result."""
    if isinstance(result.get("structuredContent"), (dict, list)):
        return result["structuredContent"]
    text = tool_text(result).strip()
    try:
        return json.loads(text)
    except ValueError:
        raise McpError("Tool returned non-JSON content")
