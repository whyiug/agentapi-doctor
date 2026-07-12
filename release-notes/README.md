# Release notes

Every future RC or stable tag must have an exact, reviewed file named
`release-notes/vX.Y.Z.md` or `release-notes/vX.Y.Z-rc.N.md` in the tagged commit.
The release workflow validates that the title binds the tag and that the file
contains non-placeholder Summary, Compatibility, Migration, Known issues,
Support window, and Verification sections. It then uses those reviewed bytes as
the GitHub Release body.

Copy [TEMPLATE.md](TEMPLATE.md) when preparing a release. Committing the template
does not authorize a release, satisfy a gate, or create release evidence.
