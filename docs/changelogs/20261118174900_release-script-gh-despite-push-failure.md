# Release script continues to GitHub release after mirror push failure

## Decisions

- Treat `git push origin` as best-effort when `origin` has multiple push URLs.
- Always run `gh release create` after gem push and local tag, even when a mirror push fails.
- Exit non-zero after a successful GitHub release when push failed, so the operator still sees the mirror problem.

## Effects

- `usr/bin/release.rb` accepts `allow_failure:` on `execute_command`.
- `spec/release_spec.rb` covers push failure then GitHub release create.
- Interrupted `2.3.0` publish path can finish the GitHub release without re-pushing the gem.

## Next

- Retry Codeberg (or other mirror) push for tag `2.3.0` when that host is reachable.

## Source

- `usr/bin/release.rb`
- `spec/release_spec.rb`
- Terminal: `make release` after RubyGems publish; Codeberg SSH closed the connection mid multi-URL push
