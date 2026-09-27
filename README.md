# xmip-core-authorize-role

Role authorization: assigns roles to an identity from its Party or its recorded value — the capability's `Subject` — or from a claim it carries, one entry per value, or the organizational unit of its name (`Assignee`), and can refuse an identity that holds none. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
