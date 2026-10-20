import json
import threading
import urllib.request
import urllib.error
import http.cookiejar

from concurrent.futures import ThreadPoolExecutor

BASE = "http://127.0.0.1:5000"

# Session A: the session that obtains and redeems the lease.
cookies_a = http.cookiejar.CookieJar()
client_a = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies_a)
)

# Direct client for requests with an explicitly supplied cookie.
direct_client = urllib.request.build_opener()


def post(path, data, client, cookie_header=None):
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    if cookie_header:
        request.add_header("Cookie", cookie_header)

    try:
        with client.open(request, timeout=10) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()

    return status, json.loads(body)


# 1. Issue one lease for Session A.
status, issued = post(
    "/api/v1/lease/issue",
    {},
    client_a,
)

print("LEASE ISSUANCE:", status)

if status != 201:
    raise SystemExit(f"Lease issuance failed: {issued}")

lease_id = issued["lease_id"]

cookie_a = "; ".join(
    f"{cookie.name}={cookie.value}"
    for cookie in cookies_a
)

if not cookie_a:
    raise SystemExit("Session A cookie was not created.")


# 2. Reproduce the intended race.
barrier = threading.Barrier(2)


def redeem():
    barrier.wait(timeout=5)

    return post(
        "/api/v1/lease/redeem",
        {"lease_id": lease_id},
        direct_client,
        cookie_a,
    )


with ThreadPoolExecutor(max_workers=2) as pool:
    futures = [pool.submit(redeem) for _ in range(2)]
    results = [future.result() for future in futures]

if not all(status == 201 for status, _ in results):
    raise SystemExit(
        "Could not obtain two receipts; confirm vulnerable mode is enabled."
    )

receipts = [body["receipt"] for _, body in results]

if receipts[0]["receipt_id"] == receipts[1]["receipt_id"]:
    raise SystemExit("Receipt IDs must be distinct.")

print("RACE SETUP: two distinct receipts obtained.")


# 3. Confirm the original receipts work.
status, result = post(
    "/api/v1/archive/mission",
    {"receipts": receipts},
    direct_client,
    cookie_a,
)

print("\nVALID RECEIPTS:", status)

if status != 200:
    raise SystemExit(f"Valid receipts rejected: {result}")

print("PASS: original receipts accepted.")


# 4. Tamper with a receipt signature.
tampered = [dict(receipt) for receipt in receipts]
tampered[0]["signature"] = "0" * 64

status, result = post(
    "/api/v1/archive/mission",
    {"receipts": tampered},
    direct_client,
    cookie_a,
)

print("\nTAMPERED SIGNATURE:", status, result)

if status != 403:
    raise SystemExit("FAIL: tampered receipt was not rejected.")

print("PASS: signature tampering rejected.")


# 5. Submit the same receipt twice.
duplicate = [receipts[0], receipts[0]]

status, result = post(
    "/api/v1/archive/mission",
    {"receipts": duplicate},
    direct_client,
    cookie_a,
)

print("\nDUPLICATE RECEIPT:", status, result)

if status != 400:
    raise SystemExit("FAIL: duplicate receipt ID was not rejected.")

print("PASS: duplicate receipt ID rejected.")


# 6. Session B attempts to reuse Session A's receipts.
cookies_b = http.cookiejar.CookieJar()
client_b = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies_b)
)

status, result = post(
    "/api/v1/archive/mission",
    {"receipts": receipts},
    client_b,
)

print("\nCROSS-SESSION REUSE:", status, result)

if status != 403:
    raise SystemExit("FAIL: another session reused the receipts.")

print("PASS: cross-session reuse rejected.")

print("\nALL INTEGRITY TESTS PASSED.")
