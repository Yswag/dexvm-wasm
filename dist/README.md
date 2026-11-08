# dist

Nothing here is committed. Artifacts are produced by

* `scripts/build.sh` / `scripts/release.sh` locally, and
* `.github/workflows/release.yml` on a `v*` tag (attached to the GitHub Release).

A plain push only uploads a build artifact (`ci.yml`), so the repository stays
binary-free and the committed tree matches the tag.
