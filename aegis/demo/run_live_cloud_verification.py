import sys
sys.path.insert(0, ".")
import os
import time
import json
import urllib.request
import urllib.error

from aegis.demo.fixtures import WEAK_PATCH, STRONG_PATCH

CLOUD_RUN_URL = os.getenv("CLOUD_RUN_URL", "https://aegis-fleet-375423947359.us-central1.run.app").rstrip("/")

def post_json(endpoint, data):
    url = f"{CLOUD_RUN_URL}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_json(endpoint):
    url = f"{CLOUD_RUN_URL}{endpoint}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    print("=" * 80)
    print("  DRIVING FULL PIPELINE AGAINST CLOUD RUN PRODUCTION INSTANCE")
    print(f"  Target: {CLOUD_RUN_URL}")
    print("=" * 80)

    ts = int(time.time())
    student_id = f"std_cloud_live_{ts}"

    # 1. Enrol student
    print(f"\n>>> [1/4] ENROL STUDENT: {student_id}")
    enrol_res = post_json("/students/enrol", {
        "student_id": student_id,
        "name": "Kelechi Nnamdi",
        "email": f"{student_id}@uniuyo.edu.ng",
        "room_id": "room_07_reflected_xss",
    })
    print(f"  --> Stage reached:   {enrol_res.get('stage')}")
    print(f"  --> Room Assigned:   {enrol_res.get('room_id')}")
    print(f"  --> Trace ID:        {enrol_res.get('trace_id')}")
    print(f"  --> Agent Response:\n{enrol_res.get('agent_response')}")

    # 2. Submit WEAK_PATCH (must fail)
    print(f"\n>>> [2/4] SUBMIT WEAK_PATCH (Expected to FAIL)")
    sub_weak_res = post_json("/webhooks/submission_received", {
        "submission_id": f"sub_weak_{ts}",
        "student_id": student_id,
        "room_id": "room_07_reflected_xss",
        "artifact": WEAK_PATCH,
    })
    print(f"  --> Stage reached:   {sub_weak_res.get('stage')}")
    print(f"  --> Trace ID:        {sub_weak_res.get('trace_id')}")
    print(f"  --> Agent Response:\n{sub_weak_res.get('agent_response')}")

    # 3. Resubmit STRONG_PATCH (must pass)
    print(f"\n>>> [3/4] RESUBMIT STRONG_PATCH (Expected to PASS)")
    sub_strong_res = post_json("/webhooks/submission_received", {
        "submission_id": f"sub_strong_{ts}",
        "student_id": student_id,
        "room_id": "room_07_reflected_xss",
        "artifact": STRONG_PATCH,
    })
    print(f"  --> Stage reached:   {sub_strong_res.get('stage')}")
    print(f"  --> Trace ID:        {sub_strong_res.get('trace_id')}")
    print(f"  --> Agent Response:\n{sub_strong_res.get('agent_response')}")

    # 4. Human Approval (if in HUMAN_REVIEW_PENDING)
    current_stage = sub_strong_res.get("stage")
    if current_stage == "HUMAN_REVIEW_PENDING":
        print(f"\n>>> [4/4] INSTRUCTOR HUMAN SIGN-OFF")
        approve_res = post_json("/webhooks/human_approved", {
            "student_id": student_id,
            "instructor_id": "prof_ekong_uniuyo",
            "approved": True,
            "comments": "Audited contextual output encoding and adversary red-team defense. Approved.",
        })
        print(f"  --> Approved:        {approve_res.get('approved')}")
        print(f"  --> Trace ID:        {approve_res.get('trace_id')}")
        print(f"  --> Agent Response:\n{approve_res.get('agent_response')}")

    # 5. Retrieve Credential Provenance
    print(f"\n>>> [5/5] FETCHING FINAL PROVENANCE FROM /credentials/...")
    audit = get_json("/audit")
    events = audit.get("events", [])
    cred_id = None
    for e in reversed(events):
        if e.get("subject") == student_id and e.get("action") == "credential:issue":
            cred_id = e.get("payload", {}).get("credential_id")
            break

    if cred_id:
        prov = get_json(f"/credentials/{cred_id}/provenance")
        print("\n================================================================================")
        print("  VERIFIABLE CREDENTIAL PROVENANCE RESPONSE (MONEY ENDPOINT):")
        print("================================================================================")
        print(json.dumps(prov, indent=2))
        print(f"\nCloud Trace Deep Link: {prov.get('cloud_trace_url')}")
    else:
        print(f"  Note: No credential event recorded yet in audit log. Total events: {len(events)}")

if __name__ == "__main__":
    main()
