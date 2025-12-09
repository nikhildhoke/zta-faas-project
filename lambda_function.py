import json, os, time, subprocess, jwt
from jwt import PyJWKClient, decode, ExpiredSignatureError, InvalidTokenError

# --- Config ---
APP_CLIENT_ID = os.getenv("APP_CLIENT_ID", "1eigb99bdtp6n8dk5a8el3ov4f")
ZTA_ENFORCE = os.getenv("ZTA_ENFORCE", "true").lower() == "true"

OPA_BIN_PATH = "/var/task/opa/opa"
OPA_POLICY_PATH = "/var/task/policy.rego"

OPA_OK = False

def _auth_header(event):
    h = event.get("headers") or {}
    return h.get("Authorization") or h.get("authorization") or ""

def _normalize_path(event):
    method = (event.get("requestContext", {}).get("http", {}).get("method") or "GET").upper()
    raw_path = event.get("rawPath") or "/"
    stage = event.get("requestContext", {}).get("stage") or ""
    if stage and raw_path.startswith(f"/{stage}"):
        path = raw_path[len(stage) + 1:] or "/"
    else:
        path = raw_path
    return method, path

def _opa_preflight():
    global OPA_OK
    if OPA_OK:
        return
    try:
        st = os.stat(OPA_BIN_PATH)
        if not (st.st_mode & 0o111):
            raise RuntimeError("opa/opa is not executable; run chmod +x before zipping")
        proc = subprocess.run(
            [OPA_BIN_PATH, "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1.5,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"opa version rc={proc.returncode} stderr={proc.stderr.decode()[:200]}")
        if not os.path.exists(OPA_POLICY_PATH):
            raise FileNotFoundError(f"policy not found at {OPA_POLICY_PATH}")
        OPA_OK = True
        print("opa_preflight=ok")
    except Exception as e:
        raise RuntimeError(f"OPA preflight failed: {e}")

def _opa_eval(input_obj: dict) -> bool:
    _opa_preflight()
    cmd = [OPA_BIN_PATH, "eval", "-I", "-f", "json", "-d", OPA_POLICY_PATH, "data.zta.allow"]
    t0 = time.time()
    proc = subprocess.run(
        cmd,
        input=json.dumps(input_obj).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3.5,
    )
    ms = int((time.time() - t0) * 1000)
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8")
        print(f"decision=error opa_ms={ms} opa_stderr={stderr[:500]}")
        raise RuntimeError(f"OPA error rc={proc.returncode}")
    out = json.loads(proc.stdout.decode("utf-8"))
    val = bool(out["result"][0]["expressions"][0]["value"])
    print(f"decision={'allow' if val else 'deny'} opa_ms={ms}")
    return val

def lambda_handler(event, context):
    try:
        if not ZTA_ENFORCE:
            method, path = _normalize_path(event)
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"ok": True, "mode": "baseline", "method": method, "path": path}),
            }

        auth = _auth_header(event)
        if not auth.startswith("Bearer "):
            return {"statusCode": 401, "body": json.dumps({"message": "Missing Bearer token"})}
        token = auth.split(" ", 1)[1]

        # Unverified parse to get issuer
        unverified = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        iss = unverified.get("iss")
        if not iss:
            return {"statusCode": 401, "body": json.dumps({"message": "Missing iss claim"})}

        # Verify signature (no 'aud' for Cognito access tokens)
        jwk_client = PyJWKClient(f"{iss}/.well-known/jwks.json")
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        claims = decode(token, signing_key, algorithms=["RS256"], issuer=iss, options={"verify_aud": False})

        # Identity binding
        if claims.get("token_use") != "access":
            return {"statusCode": 401, "body": json.dumps({"message": "Wrong token type", "token_use": claims.get("token_use")})}
        if claims.get("client_id") != APP_CLIENT_ID:
            return {"statusCode": 401, "body": json.dumps({"message": "Client mismatch", "client_id": claims.get("client_id")})}

        # Authorize via OPA
        method, path = _normalize_path(event)
        allowed = _opa_eval({"method": method, "path": path, "client": APP_CLIENT_ID, "claims": claims})
        if not allowed:
            return {"statusCode": 403, "body": json.dumps({"message": "Denied by policy"})}

        return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": json.dumps({"ok": True, "claims": claims})}

    except ExpiredSignatureError:
        return {"statusCode": 401, "body": json.dumps({"message": "Token expired"})}
    except InvalidTokenError as e:
        return {"statusCode": 401, "body": json.dumps({"message": f"Invalid token: {str(e)}"})}
    except subprocess.TimeoutExpired:
        # If OPA eval itself exceeded 3.5s, fail closed but show a clear message
        return {"statusCode": 403, "body": json.dumps({"message": "Denied by policy (OPA timeout)"})}
    except Exception as e:
        # Log a short message to caller, full details are in CloudWatch from our prints above
        return {"statusCode": 500, "body": json.dumps({"message": "Internal error"})}
