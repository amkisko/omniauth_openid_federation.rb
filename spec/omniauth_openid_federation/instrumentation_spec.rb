require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Instrumentation do
  let(:config) { OmniauthOpenidFederation::Configuration.config }

  before do
    # Reset configuration before each test
    config.instrumentation = nil
  end

  after do
    # Clean up after each test
    config.instrumentation = nil
  end

  describe ".notify" do
    context "when instrumentation is nil" do
      it "returns early without calling instrumentation" do
        config.instrumentation = nil
        expect(described_class.notify("test_event")).to be_nil
      end
    end

    context "when instrumentation is a Proc" do
      it "calls the proc with event and payload" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = [event, payload] }

        described_class.notify("test_event", data: {key: "value"}, severity: :error)

        expect(called_with).not_to be_nil
        expect(called_with[0]).to eq("test_event")
        expect(called_with[1]).to be_a(Hash)
        expect(called_with[1][:event]).to eq("test_event")
        expect(called_with[1][:severity]).to eq(:error)
        expect(called_with[1][:data]).to be_a(Hash)
        expect(called_with[1][:timestamp]).to be_a(String)
      end

      it "sanitizes sensitive data" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = payload }

        described_class.notify("test_event", data: {
          token: "secret-token",
          private_key: "secret-key",
          state: "secret-state"
        })

        expect(called_with[:data][:token]).to eq("[REDACTED]")
        expect(called_with[:data][:private_key]).to eq("[REDACTED]")
        expect(called_with[:data][:state]).to eq("[REDACTED]")
      end

      it "sanitizes nested hashes" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = payload }

        described_class.notify("test_event", data: {
          nested: {
            token: "secret-token",
            public_data: "safe"
          }
        })

        expect(called_with[:data][:nested][:token]).to eq("[REDACTED]")
        expect(called_with[:data][:nested][:public_data]).to eq("safe")
      end

      it "sanitizes arrays with hashes" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = payload }

        described_class.notify("test_event", data: {
          items: [
            {token: "secret1", name: "item1"},
            {token: "secret2", name: "item2"}
          ]
        })

        expect(called_with[:data][:items][0][:token]).to eq("[REDACTED]")
        expect(called_with[:data][:items][0][:name]).to eq("item1")
        expect(called_with[:data][:items][1][:token]).to eq("[REDACTED]")
      end

      it "includes timestamp in payload" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = payload }

        described_class.notify("test_event")

        after_time = Time.now.utc
        timestamp = Time.parse(called_with[:timestamp])
        # Timestamp should be recent (within last second)
        expect(timestamp).to be <= after_time
        expect(timestamp).to be >= (after_time - 1)
      end

      it "uses default severity :warning" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = payload }

        described_class.notify("test_event")

        expect(called_with[:severity]).to eq(:warning)
      end

      it "uses custom severity" do
        called_with = nil
        config.instrumentation = ->(event, payload) { called_with = payload }

        described_class.notify("test_event", severity: :error)

        expect(called_with[:severity]).to eq(:error)
      end
    end

    context "when instrumentation responds to :notify" do
      it "calls notify method" do
        instrumentation = double("instrumentation")
        allow(instrumentation).to receive(:notify)
        config.instrumentation = instrumentation

        described_class.notify("test_event", data: {key: "value"})

        expect(instrumentation).to have_received(:notify).with("test_event", hash_including(:event, :severity, :timestamp, :data))
      end
    end

    context "when instrumentation is logger-like" do
      it "calls error for :error severity" do
        logger = double("logger")
        allow(logger).to receive(:error)
        config.instrumentation = logger

        described_class.notify("test_event", severity: :error)

        expect(logger).to have_received(:error).with(match(/OpenID Federation Security/))
      end

      it "calls warn for :warning severity" do
        logger = double("logger")
        allow(logger).to receive(:warn)
        config.instrumentation = logger

        described_class.notify("test_event", severity: :warning)

        expect(logger).to have_received(:warn).with(match(/OpenID Federation Security/))
      end

      it "calls info for :info severity" do
        logger = double("logger")
        allow(logger).to receive(:info)
        config.instrumentation = logger

        described_class.notify("test_event", severity: :info)

        expect(logger).to have_received(:info).with(match(/OpenID Federation Security/))
      end
    end

    context "when instrumentation raises an error" do
      it "catches the error and logs a warning" do
        config.instrumentation = ->(event, payload) { raise StandardError, "Instrumentation failed" }
        allow(OmniauthOpenidFederation::Logger).to receive(:warn)

        expect { described_class.notify("test_event") }.not_to raise_error

        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(match(/Failed to notify/))
      end
    end
  end

  describe ".notify_csrf_detected" do
    it "calls notify with CSRF event and error severity" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_csrf_detected(state_param: "param", state_session: "session")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_CSRF_DETECTED)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("State parameter mismatch")
      expect(called_with[1][:data][:state_param]).to eq("[REDACTED]")
      expect(called_with[1][:data][:state_session]).to eq("[REDACTED]")
    end
  end

  describe ".notify_signature_verification_failed" do
    it "calls notify with signature verification event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_signature_verification_failed(token_type: "id_token", kid: "key-id")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_SIGNATURE_VERIFICATION_FAILED)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("JWT signature verification failed")
      expect(called_with[1][:data][:token_type]).to eq("id_token")
      expect(called_with[1][:data][:kid]).to eq("key-id")
    end
  end

  describe ".notify_decryption_failed" do
    it "calls notify with decryption event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_decryption_failed(token_type: "id_token")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_DECRYPTION_FAILED)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Token decryption failed")
    end
  end

  describe ".notify_token_validation_failed" do
    it "calls notify with token validation event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_token_validation_failed(validation_type: "claims", missing_claims: ["sub"])

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_TOKEN_VALIDATION_FAILED)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Token validation failed")
    end
  end

  describe ".notify_key_rotation_detected" do
    it "calls notify with key rotation event and warning severity" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_key_rotation_detected(jwks_uri: "https://example.com/jwks", kid: "old-key")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_KEY_ROTATION_DETECTED)
      expect(called_with[1][:severity]).to eq(:warning)
      expect(called_with[1][:data][:reason]).to include("Key rotation detected")
    end
  end

  describe ".notify_kid_not_found" do
    it "calls notify with kid not found event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_kid_not_found(kid: "missing-key", jwks_uri: "https://example.com/jwks")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_KID_NOT_FOUND)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Key ID not found")
    end
  end

  describe ".notify_entity_statement_validation_failed" do
    it "calls notify with entity statement validation event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_entity_statement_validation_failed(entity_id: "https://example.com")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_ENTITY_STATEMENT_VALIDATION_FAILED)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Entity statement validation failed")
    end
  end

  describe ".notify_fingerprint_mismatch" do
    it "calls notify with fingerprint mismatch event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_fingerprint_mismatch(
        expected_fingerprint: "expected",
        calculated_fingerprint: "calculated"
      )

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_FINGERPRINT_MISMATCH)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("fingerprint mismatch")
      expect(called_with[1][:data][:expected_fingerprint]).to eq("[REDACTED]")
      expect(called_with[1][:data][:calculated_fingerprint]).to eq("[REDACTED]")
    end
  end

  describe ".notify_trust_chain_validation_failed" do
    it "calls notify with trust chain validation event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_trust_chain_validation_failed(entity_id: "https://example.com")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_TRUST_CHAIN_VALIDATION_FAILED)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Trust chain validation failed")
    end
  end

  describe ".notify_endpoint_mismatch" do
    it "calls notify with endpoint mismatch event and warning severity" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_endpoint_mismatch(endpoint_type: "authorization", expected: "https://example.com/auth")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_ENDPOINT_MISMATCH)
      expect(called_with[1][:severity]).to eq(:warning)
      expect(called_with[1][:data][:reason]).to include("Endpoint mismatch detected")
    end
  end

  describe ".notify_unexpected_authentication_break" do
    it "calls notify with unexpected authentication break event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_unexpected_authentication_break(stage: "callback", error_message: "Unexpected error")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_UNEXPECTED_AUTHENTICATION_BREAK)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Unexpected authentication break")
    end
  end

  describe ".notify_state_mismatch" do
    it "calls notify with state mismatch event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_state_mismatch(state_param: "param", state_session: "session")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_STATE_MISMATCH)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("State parameter mismatch")
    end
  end

  describe ".notify_missing_required_claims" do
    it "calls notify with missing required claims event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_missing_required_claims(missing_claims: ["sub", "iss"], token_type: "id_token")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_MISSING_REQUIRED_CLAIMS)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Token missing required claims")
    end
  end

  describe ".notify_audience_mismatch" do
    it "calls notify with audience mismatch event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_audience_mismatch(expected_audience: "client-id", actual_audience: "wrong-id")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_AUDIENCE_MISMATCH)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Token audience mismatch")
    end
  end

  describe ".notify_issuer_mismatch" do
    it "calls notify with issuer mismatch event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_issuer_mismatch(expected_issuer: "https://example.com", actual_issuer: "https://wrong.com")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_ISSUER_MISMATCH)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Token issuer mismatch")
    end
  end

  describe ".notify_expired_token" do
    it "calls notify with expired token event and warning severity" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_expired_token(exp: Time.now.to_i - 100, current_time: Time.now.to_i)

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_EXPIRED_TOKEN)
      expect(called_with[1][:severity]).to eq(:warning)
      expect(called_with[1][:data][:reason]).to include("Token expired")
    end
  end

  describe ".notify_invalid_nonce" do
    it "calls notify with invalid nonce event" do
      called_with = nil
      config.instrumentation = ->(event, payload) { called_with = [event, payload] }

      described_class.notify_invalid_nonce(expected_nonce: "nonce1", actual_nonce: "nonce2")

      expect(called_with[0]).to eq(OmniauthOpenidFederation::Instrumentation::EVENT_INVALID_NONCE)
      expect(called_with[1][:severity]).to eq(:error)
      expect(called_with[1][:data][:reason]).to include("Nonce mismatch")
    end
  end

  describe ".sanitize_data" do
    it "returns empty hash for non-hash input" do
      result = described_class.send(:sanitize_data, nil)
      expect(result).to eq({})
    end

    it "returns empty hash for non-hash input" do
      result = described_class.send(:sanitize_data, "not a hash")
      expect(result).to eq({})
    end

    it "redacts sensitive keys" do
      data = {
        token: "secret",
        access_token: "secret",
        id_token: "secret",
        refresh_token: "secret",
        private_key: "secret",
        key: "secret",
        secret: "secret",
        password: "secret",
        authorization_code: "secret",
        code: "secret",
        state: "secret",
        nonce: "secret",
        state_param: "secret",
        state_session: "secret",
        fingerprint: "secret",
        calculated_fingerprint: "secret",
        expected_fingerprint: "secret",
        safe_data: "not redacted"
      }

      result = described_class.send(:sanitize_data, data)

      expect(result[:token]).to eq("[REDACTED]")
      expect(result[:access_token]).to eq("[REDACTED]")
      expect(result[:id_token]).to eq("[REDACTED]")
      expect(result[:refresh_token]).to eq("[REDACTED]")
      expect(result[:private_key]).to eq("[REDACTED]")
      expect(result[:key]).to eq("[REDACTED]")
      expect(result[:secret]).to eq("[REDACTED]")
      expect(result[:password]).to eq("[REDACTED]")
      expect(result[:authorization_code]).to eq("[REDACTED]")
      expect(result[:code]).to eq("[REDACTED]")
      expect(result[:state]).to eq("[REDACTED]")
      expect(result[:nonce]).to eq("[REDACTED]")
      expect(result[:state_param]).to eq("[REDACTED]")
      expect(result[:state_session]).to eq("[REDACTED]")
      expect(result[:fingerprint]).to eq("[REDACTED]")
      expect(result[:calculated_fingerprint]).to eq("[REDACTED]")
      expect(result[:expected_fingerprint]).to eq("[REDACTED]")
      expect(result[:safe_data]).to eq("not redacted")
    end

    it "handles string keys" do
      data = {"token" => "secret", "safe" => "data"}
      result = described_class.send(:sanitize_data, data)

      expect(result["token"]).to eq("[REDACTED]")
      expect(result["safe"]).to eq("data")
    end

    it "handles nested hashes" do
      data = {
        nested: {
          token: "secret",
          safe: "data"
        }
      }
      result = described_class.send(:sanitize_data, data)

      expect(result[:nested][:token]).to eq("[REDACTED]")
      expect(result[:nested][:safe]).to eq("data")
    end

    it "handles arrays with hashes" do
      data = {
        items: [
          {token: "secret1", name: "item1"},
          {token: "secret2", name: "item2"}
        ]
      }
      result = described_class.send(:sanitize_data, data)

      expect(result[:items][0][:token]).to eq("[REDACTED]")
      expect(result[:items][0][:name]).to eq("item1")
      expect(result[:items][1][:token]).to eq("[REDACTED]")
      expect(result[:items][1][:name]).to eq("item2")
    end

    it "handles arrays with non-hash values" do
      data = {
        items: ["value1", "value2"]
      }
      result = described_class.send(:sanitize_data, data)

      expect(result[:items]).to eq(["value1", "value2"])
    end
  end
end
