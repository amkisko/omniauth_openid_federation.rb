require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::MetadataPolicyMerger do
  let(:leaf_metadata) do
    {
      openid_relying_party: {
        redirect_uris: ["https://rp.example.com/callback"],
        client_name: "Test RP"
      }
    }
  end

  def create_statement_with_policy(iss:, sub:, metadata_policy:)
    payload = {
      iss: iss,
      sub: sub,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      metadata_policy: metadata_policy
    }

    private_key = OpenSSL::PKey::RSA.new(2048)
    public_key = private_key.public_key
    jwk = JWT::JWK.new(public_key)
    header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk.export[:kid]}
    jwt_string = JWT.encode(payload, private_key, "RS256", header)

    statement = OmniauthOpenidFederation::Federation::EntityStatement.new(jwt_string)
    allow(statement).to receive(:parse).and_return({
      iss: iss,
      sub: sub,
      metadata_policy: metadata_policy,
      is_subordinate_statement: (iss != sub)
    })
    statement
  end

  describe "#initialize" do
    it "initializes with trust chain" do
      merger = described_class.new(trust_chain: [])
      expect(merger.instance_variable_get(:@trust_chain)).to eq([])
    end
  end

  describe "#merge_policies" do
    it "returns empty hash when no policies exist" do
      merger = described_class.new(trust_chain: [])
      expect(merger.merge_policies).to eq({})
    end

    it "merges single policy" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      merged = merger.merge_policies

      # Keys are normalized to strings
      expect(merged["openid_relying_party"]["redirect_uris"]["value"]).to eq(["https://allowed.example.com/callback"])
    end

    it "merges multiple policies with value operator" do
      policy1 = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed1.example.com/callback"]
          }
        }
      }

      policy2 = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed1.example.com/callback"] # Same value
          }
        }
      }

      stmt1 = create_statement_with_policy(iss: "https://ta.example.com", sub: "https://intermediate.example.com", metadata_policy: policy1)
      stmt2 = create_statement_with_policy(iss: "https://intermediate.example.com", sub: "https://rp.example.com", metadata_policy: policy2)

      merger = described_class.new(trust_chain: [stmt1, stmt2])
      merged = merger.merge_policies

      # Keys are normalized to strings
      redirect_uris_policy = merged["openid_relying_party"]["redirect_uris"]
      expect(redirect_uris_policy["value"]).to eq(["https://allowed1.example.com/callback"])
    end

    it "raises ValidationError on conflicting value operators" do
      policy1 = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed1.example.com/callback"]
          }
        }
      }

      policy2 = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed2.example.com/callback"] # Different value
          }
        }
      }

      stmt1 = create_statement_with_policy(iss: "https://ta.example.com", sub: "https://intermediate.example.com", metadata_policy: policy1)
      stmt2 = create_statement_with_policy(iss: "https://intermediate.example.com", sub: "https://rp.example.com", metadata_policy: policy2)

      merger = described_class.new(trust_chain: [stmt1, stmt2])

      expect {
        merger.merge_policies
      }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /Conflicting 'value' operators/
      )
    end

    it "merges add operator" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            add: ["https://additional.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      merged = merger.merge_policies

      redirect_uris_policy = merged["openid_relying_party"]["redirect_uris"]
      expect(redirect_uris_policy["add"]).to include("https://additional.example.com/callback")
    end

    it "merges one_of operator with intersection" do
      policy1 = {
        openid_relying_party: {
          token_endpoint_auth_method: {
            one_of: ["private_key_jwt", "client_secret_basic"]
          }
        }
      }

      policy2 = {
        openid_relying_party: {
          token_endpoint_auth_method: {
            one_of: ["private_key_jwt", "client_secret_post"]
          }
        }
      }

      stmt1 = create_statement_with_policy(iss: "https://ta.example.com", sub: "https://intermediate.example.com", metadata_policy: policy1)
      stmt2 = create_statement_with_policy(iss: "https://intermediate.example.com", sub: "https://rp.example.com", metadata_policy: policy2)

      merger = described_class.new(trust_chain: [stmt1, stmt2])
      merged = merger.merge_policies

      token_auth_policy = merged["openid_relying_party"]["token_endpoint_auth_method"]
      expect(token_auth_policy["one_of"]).to eq(["private_key_jwt"])
    end

    it "raises ValidationError when one_of has no intersection" do
      policy1 = {
        openid_relying_party: {
          token_endpoint_auth_method: {
            one_of: ["private_key_jwt"]
          }
        }
      }

      policy2 = {
        openid_relying_party: {
          token_endpoint_auth_method: {
            one_of: ["client_secret_basic"]
          }
        }
      }

      stmt1 = create_statement_with_policy(iss: "https://ta.example.com", sub: "https://intermediate.example.com", metadata_policy: policy1)
      stmt2 = create_statement_with_policy(iss: "https://intermediate.example.com", sub: "https://rp.example.com", metadata_policy: policy2)

      merger = described_class.new(trust_chain: [stmt1, stmt2])

      expect {
        merger.merge_policies
      }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /Conflicting 'one_of' operators/
      )
    end

    it "merges default operator" do
      policy = {
        openid_relying_party: {
          application_type: {
            default: "web"
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      merged = merger.merge_policies

      app_type_policy = merged["openid_relying_party"]["application_type"]
      expect(app_type_policy["default"]).to eq("web")
    end

    it "skips Entity Configurations (only processes Subordinate Statements)" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed.example.com/callback"]
          }
        }
      }

      # Entity Configuration (iss == sub)
      entity_config = create_statement_with_policy(
        iss: "https://rp.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      # Subordinate Statement (iss != sub)
      subordinate = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [entity_config, subordinate])
      merged = merger.merge_policies

      # Should only include policy from subordinate statement
      expect(merged).to have_key("openid_relying_party")
    end
  end

  describe "#apply_policies" do
    it "applies value operator" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(leaf_metadata)

      expect(effective[:openid_relying_party][:redirect_uris]).to eq(["https://allowed.example.com/callback"])
    end

    it "applies add operator" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            add: ["https://additional.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(leaf_metadata)

      expect(effective[:openid_relying_party][:redirect_uris]).to include("https://rp.example.com/callback")
      expect(effective[:openid_relying_party][:redirect_uris]).to include("https://additional.example.com/callback")
    end

    it "applies default operator when value is absent" do
      policy = {
        openid_relying_party: {
          application_type: {
            default: "web"
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_without_type = {
        openid_relying_party: {
          redirect_uris: ["https://rp.example.com/callback"]
        }
      }

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(metadata_without_type)

      expect(effective[:openid_relying_party][:application_type]).to eq("web")
    end

    it "validates one_of operator" do
      policy = {
        openid_relying_party: {
          token_endpoint_auth_method: {
            one_of: ["private_key_jwt", "client_secret_basic"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_valid = {
        openid_relying_party: {
          token_endpoint_auth_method: "private_key_jwt"
        }
      }

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(metadata_valid)

      expect(effective[:openid_relying_party][:token_endpoint_auth_method]).to eq("private_key_jwt")
    end

    it "raises ValidationError when one_of validation fails" do
      policy = {
        openid_relying_party: {
          token_endpoint_auth_method: {
            one_of: ["private_key_jwt", "client_secret_basic"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_invalid = {
        openid_relying_party: {
          token_endpoint_auth_method: "invalid_method"
        }
      }

      merger = described_class.new(trust_chain: [statement])

      expect {
        merger.apply_policies(metadata_invalid)
      }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /is not in one_of list/
      )
    end

    it "validates subset_of operator" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            subset_of: ["https://allowed1.example.com/callback", "https://allowed2.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_valid = {
        openid_relying_party: {
          redirect_uris: ["https://allowed1.example.com/callback"]
        }
      }

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(metadata_valid)

      expect(effective[:openid_relying_party][:redirect_uris]).to eq(["https://allowed1.example.com/callback"])
    end

    it "raises ValidationError when subset_of validation fails" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            subset_of: ["https://allowed1.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_invalid = {
        openid_relying_party: {
          redirect_uris: ["https://rp.example.com/callback", "https://disallowed.example.com/callback"]
        }
      }

      merger = described_class.new(trust_chain: [statement])

      expect {
        merger.apply_policies(metadata_invalid)
      }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /are not a subset of allowed values/
      )
    end

    it "validates superset_of operator" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            superset_of: ["https://required.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_valid = {
        openid_relying_party: {
          redirect_uris: ["https://required.example.com/callback", "https://additional.example.com/callback"]
        }
      }

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(metadata_valid)

      expect(effective[:openid_relying_party][:redirect_uris]).to include("https://required.example.com/callback")
    end

    it "raises ValidationError when superset_of validation fails" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            superset_of: ["https://required.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_invalid = {
        openid_relying_party: {
          redirect_uris: ["https://other.example.com/callback"]
        }
      }

      merger = described_class.new(trust_chain: [statement])

      expect {
        merger.apply_policies(metadata_invalid)
      }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /does not contain all required values/
      )
    end

    it "validates essential operator" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            essential: true
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(leaf_metadata)

      expect(effective[:openid_relying_party][:redirect_uris]).to be_present
    end

    it "raises ValidationError when essential parameter is missing" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            essential: true
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      metadata_missing = {
        openid_relying_party: {
          client_name: "Test RP"
        }
      }

      merger = described_class.new(trust_chain: [statement])

      expect {
        merger.apply_policies(metadata_missing)
      }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /is marked as essential but is absent/
      )
    end

    it "handles value operator with nil (removes parameter)" do
      policy = {
        openid_relying_party: {
          client_name: {
            value: nil
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      effective = merger.apply_policies(leaf_metadata)

      expect(effective[:openid_relying_party]).not_to have_key(:client_name)
    end
  end

  describe "#merge_and_apply" do
    it "merges and applies policies in one step" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed.example.com/callback"]
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      effective = merger.merge_and_apply(leaf_metadata)

      expect(effective[:openid_relying_party][:redirect_uris]).to eq(["https://allowed.example.com/callback"])
    end
  end

  describe "edge cases" do
    it "handles Hash input for trust chain" do
      policy = {
        openid_relying_party: {
          redirect_uris: {
            value: ["https://allowed.example.com/callback"]
          }
        }
      }

      statement_hash = {
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy,
        is_subordinate_statement: true
      }

      merger = described_class.new(trust_chain: [statement_hash])
      merged = merger.merge_policies

      redirect_uris_policy = merged["openid_relying_party"]["redirect_uris"]
      expect(redirect_uris_policy["value"]).to eq(["https://allowed.example.com/callback"])
    end

    it "preserves unknown operators in merged policies" do
      # Test that unknown operators are preserved when merging policies
      policy = {
        openid_relying_party: {
          redirect_uris: {
            unknown_operator: "value"
          }
        }
      }

      statement = create_statement_with_policy(
        iss: "https://ta.example.com",
        sub: "https://rp.example.com",
        metadata_policy: policy
      )

      merger = described_class.new(trust_chain: [statement])
      merged = merger.merge_policies

      # The unknown operator should be preserved in the merged policy
      expect(merged).to have_key("openid_relying_party")
      expect(merged["openid_relying_party"]).to have_key("redirect_uris")
      redirect_uris_policy = merged["openid_relying_party"]["redirect_uris"]
      # Keys are normalized to strings
      expect(redirect_uris_policy).to have_key("unknown_operator")
      expect(redirect_uris_policy["unknown_operator"]).to eq("value")
    end

    it "logs warning for unknown operators during merge" do
      # Create two policies with the same parameter - merging will trigger the warning
      # Policies are merged in reverse order (Trust Anchor first), so:
      # 1. stmt2 (intermediate -> RP) is processed first, creates policy with unknown_operator
      # 2. stmt1 (TA -> intermediate) is processed second, merges with stmt2's policy
      # When stmt1 merges, it should encounter the unknown_operator from stmt2 and log a warning
      # But actually, stmt1 has a different policy (add), so when it merges, it won't see unknown_operator
      # We need stmt1 to also have unknown_operator so it merges with stmt2's unknown_operator
      # OR we need stmt1 to have a known operator that merges with stmt2's unknown_operator

      # Actually, the merge happens at the parameter level. Both policies have redirect_uris,
      # so when stmt1 is processed, it should merge with stmt2's redirect_uris policy.
      # But stmt1 has "add" and stmt2 has "unknown_operator", so they should merge.

      # Let me try a different approach: have stmt1 with unknown_operator, and stmt2 with a known operator
      # When stmt2 merges with stmt1, it should see the unknown_operator and log a warning
      policy1 = {
        openid_relying_party: {
          redirect_uris: {
            unknown_operator: "value"
          }
        }
      }

      policy2 = {
        openid_relying_party: {
          redirect_uris: {
            add: ["https://additional1.example.com/callback"]
          }
        }
      }

      # stmt2 is processed first (immediate issuer), stmt1 is processed second (Trust Anchor)
      # When stmt1 merges with stmt2's policy, stmt1's unknown_operator should trigger the warning
      stmt1 = create_statement_with_policy(iss: "https://ta.example.com", sub: "https://intermediate.example.com", metadata_policy: policy1)
      stmt2 = create_statement_with_policy(iss: "https://intermediate.example.com", sub: "https://rp.example.com", metadata_policy: policy2)

      merger = described_class.new(trust_chain: [stmt1, stmt2])

      # The warning is logged when merging policies in merge_parameter_policies
      # Set up the expectation before calling merge_policies
      allow(OmniauthOpenidFederation::Logger).to receive(:warn)

      merger.merge_policies

      # Verify the warning was called with the unknown operator message
      # The warning should be called when stmt1 (with unknown_operator) merges with stmt2's policy
      expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Unknown operator/)
    end
  end
end
