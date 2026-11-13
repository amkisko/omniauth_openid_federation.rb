# Exclude examples from gem and defer tasks require

## Decisions

- Drop `examples/**/*` from `omniauth_openid_federation.gemspec` `spec.files`.
- Stop eager-requiring `tasks_helper` from the main gem entry.
- Add `require "omniauth_openid_federation/tasks"` for rake and CLI tooling.

## Effects

- Packaged gem no longer includes examples; repository `examples/` remains the source.
- Rake tasks and `examples/integration_test_flow.rb` require the tasks entrypoint.
- Specs: packaging contract, subprocess tasks entrypoint contract; suite loads tasks via `spec/support/tasks_entrypoint.rb`.
- Before/after packaging freeze (`tmp/packaging-before.json`, `tmp/packaging-after.json`): compressed gem 150016 to 114688 bytes; payload apparent 690558 to 526663 bytes; `du -sk` 900 to 708; examples absent after.
- Cold-require freeze (`tmp/cold-require-after.json`, n=5): main loads 59 federation features, TasksHelper absent; tasks entry loads 66 features including 7 task-related paths.

## Next

- Keep examples out of the gem on future releases.
- Optional follow-up: lazy/autoload unused federation modules after a named series prove.

## Source

- `docs/reviews/20261113121600_gem-size-thin-probe-claims-audit.md`
- `omniauth_openid_federation.gemspec`
- `lib/omniauth_openid_federation/tasks.rb`
- `spec/omniauth_openid_federation/packaging_spec.rb`
- `spec/omniauth_openid_federation/tasks_entrypoint_spec.rb`
