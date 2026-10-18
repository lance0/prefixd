# Vendored anti-slop Oxlint plugin

Source: [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop) by Dillon
Mulroy, commit `13909c9e07590f5a85d93c62712259fe14a883f7`.

Installed with that commit's `skills/install-anti-slop/scripts/install.mjs`
(fresh install, run from `frontend/`). It copied
`skills/install-anti-slop/assets/anti-slop/` verbatim to this directory.

## Installed paths

- `index.ts`: generic plugin entry point, registered in `frontend/.oxlintrc.json`
  as `anti-slop`.
- `rules/`, `shared/`: generic rules and helpers.
- `vendor/eslint-stylistic/`: vendored padding rule with its own `LICENSE` and
  `UPSTREAM.md`.
- `effect/`: opt-in Effect plugin. Copied by the installer but not registered,
  because the dashboard has no direct `effect` dependency.

## Dependencies

`oxlint` and `@oxlint/plugins` are pinned exactly to `1.88.0`, the current
release when installed, as the skill prescribes. The upstream repository tests
against `1.78.0`.

## Deviations

- `LICENSE`: the upstream repository's root MIT license, copied verbatim. The
  installer copies only the nested ESLint Stylistic license.
- `package.json`: `{"type": "module"}` scoped to this directory, so Node loads
  the plugin as ESM without a `MODULE_TYPELESS_PACKAGE_JSON` warning on every
  lint run. The dashboard's own `package.json` is unchanged.
- `frontend/tsconfig.json` excludes this directory. The plugin imports sibling
  modules with `.ts` extensions, which the dashboard's compiler options reject
  (TS5097). The plugin is type-checked upstream.
- Plugin source is otherwise unmodified.

## Updating

Follow the upstream `install-anti-slop` skill's update procedure against an
explicit upstream commit, then update this record.
