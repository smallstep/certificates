# Refresh one instance's administration cache

`POST /admin/resources/reload` refreshes the handling instance's in-memory
provisioners and administrators from the existing administration database. It
reuses `Authority.ReloadAdminResources`; it does not restart the server, reload
`ca.json`, rotate keys, or broadcast to other instances.

Remote administration must be enabled (`authority.enableAdmin: true`), and the
caller must authenticate as a **super administrator** using the existing Admin
API X5C JWT mechanism. This is not an OAuth access token, an ordinary bearer
token, or merely a TLS client certificate. Ordinary administrators are rejected.
The signed JWT audience must match the request URL. Each request needs a fresh
token because Admin API tokens are protected against replay.

The endpoint accepts no configuration payload. Success is HTTP 200 with
`{"status":"ok"}` after the refresh completes. Authentication/authorization
failures follow the existing Admin API's HTTP 401 convention. Refresh failures
return an Admin API HTTP 500 error. Requests using GET do not refresh anything.

## Multiple instances

After adding, changing or deleting provisioners or administrators through the
Admin API, an external administration workflow can refresh each CA instance.
Address every instance directly; repeated calls to a load-balanced URL do not
guarantee that all instances will be reached.

For example, with a shared service certificate for `ca.example.test`, target
each node's address while retaining that hostname for TLS and the JWT audience:

```bash
# Supply independently generated, short-lived Admin API X5C JWTs. Never log them.
curl --fail-with-body --cacert root-ca.crt \
  --resolve ca.example.test:443:192.0.2.10 \
  --request POST \
  --header "Authorization: ${ADMIN_X5C_TOKEN_A}" \
  https://ca.example.test/admin/resources/reload

curl --fail-with-body --cacert root-ca.crt \
  --resolve ca.example.test:443:192.0.2.11 \
  --request POST \
  --header "Authorization: ${ADMIN_X5C_TOKEN_B}" \
  https://ca.example.test/admin/resources/reload
```

Use the normal Admin API signing process with a valid super-admin certificate
and private key to generate these tokens. This change does not add a CLI command
or a new token format. Both tokens have the audience
`https://ca.example.test/admin/resources/reload`, but different unique token IDs.
Do not disable TLS verification. In scripts, avoid placing tokens in command
arguments on systems where process arguments are visible to other users.

Check each response and verify the expected configuration on every instance.
A failure on one node must not be treated as successful cluster synchronization.
Retry that node with a fresh token after resolving the error.

## Scope and limitations

This is an explicit per-instance administrative action, **not automatic cache
coherence**. Changes made outside the administration workflow can still leave
other instances stale. An administrator/provisioner removed in the database may
remain usable on an instance until that instance refreshes. At least one
recognized super administrator must remain available to authenticate the refresh.

The existing cache mutex serializes refreshes with local Admin API mutations.
Requests needing that mutex may wait while database reads and provisioner
initialization run; this is not a lock-free operation. Already authorized
requests are not canceled. A failed collection build leaves the previous cache
installed. Existing provisioner-initialization behavior is unchanged: individual
initialization failures result in disabled `Uninitialized` provisioners.

The database interface reads provisioners/admins separately, so this operation
is not a cross-table transaction or an all-replica write barrier. It does not
refresh authority-wide policy engines or dynamically install protocol listeners.

No polling worker, new configuration option, database schema change, PostgreSQL
notification dependency, Terraform hook, or per-replica routing is added by this
contribution. Deployment tooling can invoke the endpoint, but this API change
does not configure that workflow automatically.
