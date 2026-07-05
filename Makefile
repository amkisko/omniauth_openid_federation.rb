.PHONY: release lint test audit integration-test clean

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

clean:
	rm -rf coverage
	rm -rf tmp/cache tmp/polyrun_failures tmp/coverage_metrics tmp/integration_test
	rm -f tmp/rspec-*.json tmp/*.log tmp/test_entity.jwt
	rm -f spec/examples.txt
	rm -f *.gem
	rm -rf log/*
	rm -rf .pray/cache
