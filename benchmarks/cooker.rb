# frozen_string_literal: true

# Pressure-cooker harness for amkisko/pressure-benchmarking.
#
#   SCENARIO=calibrate|baseline|stress|propose|measure|gate|write|prove \
#     LOAD=L0|L1 SAMPLES=3 bundle exec ruby benchmarks/cooker.rb
#
# Binding:
# - measure: this file (SCENARIO=measure)
# - self-test: SCENARIO=calibrate
# - ceilings: benchmarks/ceilings.json
# - load axis: entity-statement / key-resolve repetitions (ops)
# - samples-per-load: 3
# - min episode iterations: 10
# - propose-basis: median * 1.15
# - Memory probe class: process_lifetime
# - network: not_in_scope

require "json"
require "fileutils"
require "openssl"
require "jwt"
require "rack"
require "polyrun/benchmark/pressure"
require_relative "../lib/omniauth_openid_federation"
require_relative "../lib/omniauth_openid_federation/rack_endpoint"

module OmniauthOpenidFederation
  module Benchmarks
    module Cooker
      ROOT = File.expand_path("..", __dir__)
      CEILINGS = File.join(ROOT, "benchmarks", "ceilings.json")
      DEFAULT_SAMPLES = 3
      HEADROOM = 1.15
      LOADS = {
        "L0" => 50,
        "L1" => 200
      }.freeze

      module_function

      def run!(scenario:, load_name: "L0", samples: DEFAULT_SAMPLES)
        configure_endpoint!
        ops = LOADS.fetch(load_name)
        case scenario
        when "calibrate" then calibrate!
        when "baseline", "stress", "measure", "prove"
          result = measure_load!(ops, samples, label: "#{scenario}_#{load_name}")
          puts JSON.pretty_generate(result)
        when "propose"
          result = measure_load!(ops, samples, label: "propose_#{load_name}")
          ceilings = Polyrun::Benchmark::Pressure::Cooker.propose_ceilings(result["series"], headroom: HEADROOM)
          puts JSON.pretty_generate({"series" => result["series"], "proposed_ceilings" => ceilings})
        when "gate"
          result = measure_load!(ops, samples, label: "gate_#{load_name}")
          ceilings = Polyrun::Benchmark::Pressure::Cooker.load_ceilings(CEILINGS)
          report = Polyrun::Benchmark::Pressure::Cooker.gate(result, ceilings.fetch("ceilings"))
          puts JSON.pretty_generate(report)
          exit(report["pass"] ? 0 : 1)
        when "write"
          result = measure_load!(ops, samples, label: "write_#{load_name}")
          ceilings = Polyrun::Benchmark::Pressure::Cooker.propose_ceilings(result["series"], headroom: HEADROOM)
          Polyrun::Benchmark::Pressure::Cooker.write_ceilings!(
            CEILINGS,
            ceilings,
            meta: {
              "load" => load_name,
              "ops" => ops,
              "propose_basis" => "median",
              "headroom" => HEADROOM,
              "memory_probe_class" => "process_lifetime",
              "network" => "not_in_scope"
            }
          )
          puts "wrote #{CEILINGS}"
        else
          raise ArgumentError, "Unknown SCENARIO=#{scenario}"
        end
      end

      def calibrate!
        # Meter self-test: stages must have distinct wall times in known_rank order.
        stages = [
          ["noop", 1, -> { 1 }],
          ["sleep_2ms", 2, -> { sleep(0.002) }],
          ["sleep_6ms", 3, -> { sleep(0.006) }],
          ["sleep_12ms", 4, -> { sleep(0.012) }]
        ]
        report = Polyrun::Benchmark::Pressure::Cooker.calibrate!(stages)
        puts report["report"]
        exit(report["pass"] ? 0 : 1)
      end

      def measure_load!(ops, samples, label:)
        endpoint = OmniauthOpenidFederation::RackEndpoint.new
        env = Rack::MockRequest.env_for("/openid-federation")
        pem = @signing_key.to_pem
        callable = -> { OpenSSL::PKey::RSA.new(pem) }

        Polyrun::Benchmark::Pressure::Cooker.measure_samples(
          n: samples,
          label: label,
          ops: ops,
          extras: {"basis" => "median", "network" => "not_in_scope"}
        ) do
          ops.times do
            OmniauthOpenidFederation::KeyResolver.resolve(callable)
            endpoint.call(env)
          end
        end
      end

      def configure_endpoint!
        @signing_key = OpenSSL::PKey::RSA.new(2048)
        encryption_key = OpenSSL::PKey::RSA.new(2048)
        issuer = "https://rp.example.com"
        jwks = {
          "keys" => [
            OmniauthOpenidFederation::Utils.rsa_key_to_jwk(@signing_key, use: "sig").transform_keys(&:to_s),
            OmniauthOpenidFederation::Utils.rsa_key_to_jwk(encryption_key, use: "enc").transform_keys(&:to_s)
          ]
        }
        OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
        OmniauthOpenidFederation::FederationEndpoint.configure do |config|
          config.issuer = issuer
          config.subject = issuer
          config.private_key = @signing_key
          config.signing_key = @signing_key
          config.encryption_key = encryption_key
          config.jwks = jwks
          config.metadata = {
            "openid_relying_party" => {
              "redirect_uris" => ["#{issuer}/cb"],
              "jwks_uri" => "#{issuer}/.well-known/jwks.json",
              "signed_jwks_uri" => "#{issuer}/.well-known/signed-jwks.json"
            }
          }
        end
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  OmniauthOpenidFederation::Benchmarks::Cooker.run!(
    scenario: ENV.fetch("SCENARIO", "calibrate"),
    load_name: ENV.fetch("LOAD", "L0"),
    samples: Integer(ENV.fetch("SAMPLES", "3"))
  )
end
