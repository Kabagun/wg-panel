# Family DNS exception requests

An approved user with family protection can submit a domain and an optional
comment through **DNS exception requests**. Submission creates a private pending
record. It does not change filtering or publish a domain.

The administrator sees the queue on the existing family DNS page and receives a
silent Telegram notification with approval and rejection buttons. Telegram uses
the existing authenticated administrator webhook; a callback from another actor
or chat cannot review a request. Slow DNS application runs in the bounded background
executor, outside the webhook response.

Approval uses the existing shared DNS helper, a fresh generation and its established
application/backup pipeline. The UI and Telegram notification explicitly state that
the exception allows the domain and its subdomains for **all** users of family
protection. The request becomes approved only when the helper confirms applied
state. Rejection never changes DNS. Failed application remains retryable, and
repeated callbacks cannot blindly apply the same change again.

Users see only records bound to their current account identity. Recreating an
account does not inherit its old requests. Paused, removed or unapproved accounts
cannot submit or complete stale requests. The device-only Happ page capability
does not grant submission rights: sending a request requires normal authentication.

Requests are stored privately in `family_dns_requests.json` below the configured
data directory. An OS file lock and persisted application claim serialize decisions
without holding store locks across helper calls. Pending requests are capped per
account and the overall history is bounded. Notification backpressure does not
delete a submitted request; the web queue remains available.

Only reviewed domains flow through the existing DNS publication pipeline. Request
comments, usernames, account identities and review history are not sent to the
domain-list Git repository.
