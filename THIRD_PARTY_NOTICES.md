# Third Party Notices

takeWxapkg can optionally be built with a local wx decompiler runtime under
`vendor/wx_decompiler_runtime/`.

If you distribute a build that includes this optional runtime, review and comply
with the runtime's upstream licenses before publishing the binary.

Known local runtime source used during development:

- Project: wedecode
- Repository: https://github.com/biggerstar/wedecode
- License: GPL-3.0-or-later

The runtime directory is ignored by Git by default. This repository is intended
to publish takeWxapkg's own Python desktop application source separately from
optional third-party runtime bundles.
