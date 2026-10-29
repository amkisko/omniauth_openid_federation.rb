require "spec_helper"

RSpec.describe OmniauthOpenidFederation::HttpClient do
  let(:connection) { instance_double(HTTP::Connection, close: nil) }
  let(:response) { HTTP::Response.new(status: 200, version: "1.1", connection: connection) }
  let(:client) { instance_double(HTTP::Client, get: response) }

  before do
    stub_const("OmniauthOpenidFederation::Constants::MAX_HTTP_RESPONSE_BODY_BYTES", 32)
    allow(HTTP::Client).to receive(:new).and_return(client)
    allow(client).to receive(:timeout).and_return(client)
  end

  it "stops reading an unbounded response as soon as it exceeds the byte ceiling" do
    reads = 0
    allow(connection).to receive(:readpartial) do
      reads += 1
      raise "read beyond the byte ceiling" if reads > 2

      "a" * 17
    end

    expect { described_class.get("https://example.test/data", max_retries: 0) }
      .to raise_error(OmniauthOpenidFederation::NetworkError, /body exceeds limit/)
    expect(connection).to have_received(:close)
  end

  it "keeps a bounded response readable by its caller" do
    chunks = ["hello", " world"]
    allow(connection).to receive(:readpartial) { chunks.shift || raise(EOFError) }

    result = described_class.get("https://example.test/data", max_retries: 0)

    expect(result.body.to_s).to eq("hello world")
    expect(result.status.code).to eq(200)
  end
end
