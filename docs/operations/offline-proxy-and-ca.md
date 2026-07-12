# Offline, Proxy, and Enterprise CA

Offline is a product mode, not “the network happened to be unavailable.” A
locked run resolves packs, profiles, drivers, requirements, fixtures, schemas,
and dependencies from an explicit local cache and fails with a precise missing
object digest when closure is incomplete.

Proxy support must separate target HTTP traffic, dependency acquisition, and
Registry traffic. `NO_PROXY` handling, redirect validation, and target identity
remain explicit; a proxy does not authorize a second target. Credentials must
be secret references, never embedded in config or reports.

Enterprise CA support accepts an explicit trust bundle for the scoped target or
service. It must not disable TLS verification, mutate the system trust store, or
silently combine unrelated private roots. Reports record the trust-bundle
digest, not its private contents.

No stable CLI flags are documented yet. Generated reference will name exact
configuration fields only after the config contract is frozen.
