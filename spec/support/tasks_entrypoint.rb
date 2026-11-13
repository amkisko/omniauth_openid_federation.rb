# frozen_string_literal: true

# Task helper and rake specs need the deferred tooling entrypoint.
# Main gem require intentionally omits TasksHelper; see tasks_entrypoint_spec.
require "omniauth_openid_federation/tasks"
