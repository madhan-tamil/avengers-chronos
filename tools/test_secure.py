import json
import threading
import urllib.request
import urllib.error
import http.cookiejar

from concurrent.futures import ThreadPoolExecutor

BASE = "http://127.0.0.1:5000"

cookies = http.cookiejar.CookieJar()

session_client = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies)
)

http_client = urllib.request.build_opener()


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


# 1. Issue one lease using a new session.
status, issued = post(
    "/api/v1/lease/issue",
    {},
    session_client,
)

print("LEASE ISSUANCE:", status)

if status != 201:
    raise SystemExit(f"Lease issuance failed: {issued}")

lease_id = issued["lease_id"]

cookie_header = "; ".join(
    f"{cookie.name}={cookie.value}"
    for cookie in cookies
)

if not cookie_header:
    raise SystemExit("No session cookie was received.")

print("Lease lifetime:", issued["lifetime_ms"], "ms")


# 2. Prepare two simultaneous redemption requests.
barrier = threading.Barrier(2)


def redeem():
    barrier.wait(timeout=5)

    return post(
        "/api/v1/lease/redeem",
        {"lease_id": lease_id},
        http_client,
        cookie_header,
    )


with ThreadPoolExecutor(max_workers=2) as executor:
    futures = [
        executor.submit(redeem),
        executor.submit(redeem),
    ]

    results = [future.result() for future in futures]


for number, (status, body) in enumerate(results, start=1):
    print(f"\nREDEMPTION {number}: HTTP {status}")
    print(json.dumps(body, indent=2))


# 3. Secure behavior: exactly one request succeeds.
statuses = sorted(status for status, _ in results)

if statuses != [201, 409]:
    raise SystemExit(
        f"FAIL: Expected one 201 and one 409; got {statuses}"
    )

successful_receipts = [
    body["receipt"]
    for status, body in results
    if status == 201
]

if len(successful_receipts) != 1:
    raise SystemExit("FAIL: Expected exactly one receipt.")

print("\nPASS: Concurrent redemption is protected.")


# 4. One receipt must not unlock the archive.
status, archive = post(
    "/api/v1/archive/mission",
    {"receipts": successful_receipts},
    http_client,
    cookie_header,
)

print("\nARCHIVE RESPONSE:", status)
print(json.dumps(archive, indent=2))

if status != 400:
    raise SystemExit("FAIL: Archive accepted an incomplete receipt list.")

print("\nSUCCESS: Secure mode prevents the intended exploit.")
