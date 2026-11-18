# Opengrep stage

Opengrep reads the code of the target with two sets of rules.

| Path | Content |
| --- | --- |
| `gitlab/` | A copy of the open GitLab SAST rules, at the commit in `gitlab/SOURCE.json`. Do not edit: `update-rules.sh` writes it. |
| `gitlab-excluded.txt` | The GitLab rules that are not copied, each with its reason. |
| `update-rules.sh` | Copies the rules again. The workflow `update-rules` runs it each month and opens a pull request. |
| `rules/` | Our own rules. Each rule `<name>.yml` has its test file `<name>.<ext>`, with `ruleid:` and `ok:` lines. |
| `Dockerfile` | The image: Debian by digest, the Opengrep binary by its sha256. |
| `stage.json` | The stage. |

## Gravities

`"gravities"` in `stage.json` sets the gravity of a rule over the gravity
that the rule gives. GitLab gives "Medium" to the rules below. CI scan
blocks on them, because an AI turns off the certificate check to "make it
work":

- `java_endpoint_rule-X509TrustManager`
- `java_endpoint_rule-HostnameVerifier`
- `rules_lgpl_javascript_crypto_rule-node-tls-reject`

A test checks that each rule in `"gravities"` exists. A rename by GitLab
makes the test fail in the monthly pull request.

## The target cannot silence a rule

- `--disable-nosem`: `nosemgrep` comments have no effect.
- `--x-ignore-semgrepignore-files` and `--no-git-ignore`: `.semgrepignore`,
  `.opengrepignore` and `.gitignore` of the target are not read.
- `--max-target-bytes=0`: no file is skipped for its size.

Opengrep needs a `/tmp` to work: the stage asks for one (`"tmp": true`). It
is in memory, empty at the start, and deleted at the end.
