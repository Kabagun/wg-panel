# Proposals for Smart VPN

Approved, active users can propose a public domain and an optional comment for
the shared Smart VPN list. Family protection is not required for this workflow.
Submitting a proposal does not edit routing or DNS.

The administrator approves or rejects through the managed Smart VPN list page or
the existing authenticated Telegram administrator callback. Approval applies a
fresh revision-guarded managed-list edit and schedules the existing asynchronous
GitHub publisher. The active local list does not wait for GitHub. Publication
status remains visible on the existing administration page.

After a subscription refresh, matching domains follow the VPN route in Smart
mode. Country-bypass and full-tunnel modes retain their existing behavior. The
home router is not synchronized automatically.

This process does not change family DNS. A domain blocked by family DNS needs its
own separately reviewed DNS exception; routing approval does not unblock it.

The guarded request service uses a separate `smart_vpn_requests.json` namespace
with the same private bounded schema, lifecycle validation and application claims
as DNS proposals. The existing DNS file and default API remain compatible. Pending
duplicates, terminal callback repeats and cross-namespace IDs cannot accidentally
apply a request to the other list. Comments and account details do not enter the
published domain-list repository.
