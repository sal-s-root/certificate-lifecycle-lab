# Certificate replacement exercise

1. Run `make test`. Treat a nonzero exit as a failed acceptance check.
2. Inspect `test_replacement_changes_identity_on_same_endpoint`: the initial
   listener is stopped, a new context loads a newly signed certificate and key,
   and the listener starts again on the same loopback port.
3. Confirm both requests passed CA and hostname verification and returned different
   certificate serial numbers. Serial changes alone do not establish trust.
4. Inspect the future-time check: an expired leaf fails even with the correct CA;
   the replacement remains valid at that same verification time.

## Applying the lesson to a real service

Identify the actual certificate owner and renewal mechanism first. Check the
replacement chain, names, validity interval, and key pair before changing a service.
Keep the previous configuration available for rollback. Use the service's documented
reload procedure, then verify it from a separate client with normal validation.
Do not copy the lab CA or private keys into a production trust store.

The lab tests stop/start replacement and a short interruption. It does not prove
zero downtime, safe rollback of an external service, successful revocation, or
integration with a load balancer or certificate issuer.
