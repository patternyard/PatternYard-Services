# Compatibility contracts

`backend-api-routes.json` is generated from the current Express route source by `tools/inventory-backend.mjs`. Each route moves through the fixed statuses `unimplemented`, `parity-tested`, `shadowing`, `cut-over`, or `retired`; a route is never considered complete from implementation alone.

Fixtures added here must be synthetic and must not contain email addresses, credentials, tokens, IP addresses, private project data, or other production identifiers.
