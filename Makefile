.PHONY: release lint test spec-quality audit integration-test clean

release:
	ruby usr/bin/release.rb

lint:
	bundle exec rubocop
	bundle exec rbs validate

audit:
	bundle exec bundle audit check --update
	@set -e; for gemfile in gemfiles/{ruby,truffleruby,rails6,rails72,rails8}.gemfile; do \
		echo "==> $$gemfile"; \
		BUNDLE_GEMFILE="$$gemfile" bundle install; \
		BUNDLE_GEMFILE="$$gemfile" bundle exec bundle audit check; \
	done
	@if ruby -e 'exit((Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("4.0.0")) ? 0 : 1)'; then \
		echo "==> gemfiles/rails8_ruby4.gemfile"; \
		BUNDLE_GEMFILE=gemfiles/rails8_ruby4.gemfile bundle install; \
		BUNDLE_GEMFILE=gemfiles/rails8_ruby4.gemfile bundle exec bundle audit check; \
	else \
		echo "==> skipping gemfiles/rails8_ruby4.gemfile (Ruby 4.0+ required)"; \
	fi

test:
	bundle exec appraisal rails8 -- bundle exec polyrun parallel-rspec --workers 5 --merge-failures -c polyrun.yml

spec-quality:
	bundle exec appraisal rails8 -- env POLYRUN_COVERAGE=1 POLYRUN_MERGE_SPEC_QUALITY=1 \
		bundle exec polyrun parallel-rspec --workers 5 --merge-spec-quality -c polyrun.yml
	bundle exec polyrun report-spec-quality -i coverage/polyrun-spec-quality.json -c config/polyrun_spec_quality.yml

integration-test:
	bundle exec ruby examples/integration_test_flow.rb

clean:
	rm -rf coverage
	rm -f coverage/polyrun-spec-quality-fragment-*.jsonl coverage/polyrun-spec-quality.json
	rm -rf tmp/cache tmp/polyrun_failures tmp/coverage_metrics tmp/integration_test
	rm -f tmp/rspec-*.json tmp/*.log tmp/test_entity.jwt
	rm -f spec/examples.txt
	rm -f *.gem
	rm -rf log/*
	rm -rf .pray/cache
