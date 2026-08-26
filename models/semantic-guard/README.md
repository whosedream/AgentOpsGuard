# Semantic guard model directory

This directory is a local deployment mount. Model weights and tokenizer files are intentionally
ignored by Git. The pinned source and expected hashes are recorded in `manifest.json`.

Wolf Defender is released under Apache-2.0; the local copy is in `LICENSE`. It is derived from
[`jhu-clsp/mmBERT-base`](https://huggingface.co/jhu-clsp/mmBERT-base), whose MIT terms continue to
apply to the upstream portions. The publisher's model card retains that attribution.

The current model is approved for `shadow` evaluation only. It must not be configured in
`enforce` mode until a new frozen evaluation passes the promotion gates in
`specs/semantic-scanner-v1.md`.
