.PHONY: release lint test audit integration-test

release:
	ruby usr/bin/release.rb

lint:
	bundle exec rubocop
	bundle exec rbs validate

audit:
	bundle exec bundle audit check --update

test:
	bundle exec polyrun parallel-rspec --workers 5 --merge-failures

integration-test:
	bundle exec ruby examples/integration_test_flow.rb
