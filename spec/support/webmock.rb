begin
  require "webmock/rspec"
  # Block ALL HTTP requests including localhost
  # All requests must be explicitly stubbed with WebMock
  WebMock.disable_net_connect!(allow_localhost: false)
rescue LoadError
  warn "webmock not available; real HTTP connections are not blocked in this run"
end
