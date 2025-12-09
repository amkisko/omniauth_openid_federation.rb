# Running Tests

## Using rspec

All tests should be run using `bundle exec appraisal rails8 rspec`

```bash
# Run all tests
bundle exec appraisal rails8 rspec

# Run with fail-fast (stop on first failure)
bundle exec appraisal rails8 rspec --fail-fast

# For verbose output
DEBUG=1 bundle exec appraisal rails8 rspec

# Show zero coverage lines
SHOW_ZERO_COVERAGE=1 bundle exec appraisal rails8 rspec

# Run single spec file at exact line number
DEBUG=1 bundle exec appraisal rails8 rspec spec/path/to/spec_file.rb:10
```

## RSpec Testing Guidelines

### Spec File Organization Strategies

This gem uses the **"Split Specs"** approach (Method-as-File) for complex classes. There are three main approaches to organizing RSpec specs:

#### 1. The "Standard" Consensus (Mirroring) - Default for Simple Classes

The default expectation for most Ruby gems. The file structure in `spec/` mirrors `lib/` exactly 1-to-1.

```
lib/
└── omniauth_openid_federation/
    └── client.rb

spec/
└── omniauth_openid_federation/
    └── client_spec.rb
```

**Best For:** Small to medium-sized classes (< 300 lines, < 10 methods)

**Why it's consensus:** Zero cognitive load. If you see `lib/auth/parser.rb`, tests are in `spec/auth/parser_spec.rb`.

**The Problem:** As classes grow, `client_spec.rb` becomes a 2,000+ line "god object" that's hard to navigate.

#### 2. The "Split Specs" Approach (Method-as-File) - Used in This Gem

For complex classes where a single file becomes unmanageable. Create a directory named after the class/module, and files named after methods (or behaviors).

```
lib/
└── omniauth_openid_federation/
    └── strategy.rb      # Defines OmniAuth::Strategies::OpenIDFederation

spec/
└── omniauth_openid_federation/
    └── strategy/        # Directory matches the class name
        ├── authorize_uri_spec.rb
        ├── callback_phase_spec.rb
        └── client_jwk_signing_key_spec.rb
```

**Best For:** Complex core classes (> 500 lines, > 10 methods, high cyclomatic complexity)

**Pros:**
- **Focus:** Only load context for the specific method you're fixing
- **Git History:** Easier to see changes to specific method logic
- **Navigation:** Quick to find tests for a specific method

**Cons:**
- **Discovery:** New contributors might look for `client_spec.rb` and get confused
- **Shared Contexts:** May duplicate setup code across files (mitigate with `spec/support/shared_contexts`)

**Key Requirement:** Ensure the class is loaded in a main spec file or shared context.

#### 3. The "Subject-Based" or "Behavioral" Approach

Focuses on features/scenarios rather than method names. Popular in gems heavy on business logic.

```
spec/
└── omniauth_openid_federation/
    └── authentication_flow/
        ├── successful_authorization_spec.rb  # Tests multiple methods interacting
        ├── token_exchange_error_spec.rb
        └── csrf_protection_spec.rb
```

**Best For:** Integration-heavy gems where testing "Method A" in isolation is less useful than testing "Scenario B"

#### Decision Matrix

| If your class is... | Use Approach... |
| :--- | :--- |
| Standard (under 300 lines, < 10 methods) | #1 Mirroring (Stick to this until it hurts) |
| A "God Class" (complex core, > 500 lines) | #2 Split Specs (Method-as-File) |
| A Process/Workflow (integration-heavy) | #3 Behavioral (Group by outcome) |

### Core Philosophy: Behavior Verification vs. Implementation Coupling

The fundamental principle of refactoring-resistant testing is the distinction between **what** a system does (Behavior) and **how** it does it (Implementation).

- **Behavior:** Defined by the Public Contract—the inputs accepted by the System Under Test (SUT) and the observable outputs or side effects it produces at its architectural boundaries.
- **Implementation:** Encompasses internal control flow, private helper methods, auxiliary data structures, and the specific sequence of internal operations.

> **Principle:** True refactoring resistance is achieved only when the test suite is agnostic to the SUT's internal composition.

When a test couples itself to implementation details—for instance, by asserting that a specific private method was called or by mocking an internal helper—it violates encapsulation. Such tests verify that the code *looks* a certain way, not that it *works*. This leads to **"False Negatives"** or **"Fragile Tests,"** where a test fails simply because a developer renamed a private method or optimized a loop, even though the business logic remains correct.

### Core Principles

- **Always assume RSpec has been integrated** - Never edit `rails_helper.rb` or `spec_helper.rb` or add new testing gems
- **Test Behavior, Not Implementation** - Verify the public contract, not internal structure
- **Refactoring Resistance** - Tests should survive internal refactoring without modification
- Keep test scope minimal - start with the most crucial and essential tests
- Never test features that are built into Ruby or external gems
- Never write tests for performance unless specifically requested
- Isolate external dependencies (HTTP calls, file system, time) at architectural boundaries only

### Practical Metrics and Heuristics

#### The "Danger Zone" Metrics (When to Split)

These are the practical thresholds where files become hard to read/maintain, triggering a refactor or the split approach.

| Metric | Code (lib/) | Specs (spec/) | Notes |
| :--- | :--- | :--- | :--- |
| **Lines per File** | 100 - 300 | 300 - 500 | At 500+ lines, a spec file becomes a "scroll nightmare." At 1,000+, it's a "God Object." |
| **Lines per Method/Example** | 5 - 10 | 10 - 20 | `it` blocks should be short. If an `it` block is >15 lines, you're testing too many things or setup is complex. |
| **Methods per Class** | ~10 - 20 | N/A | For specs, this translates to "Examples per Describe block." |

#### Strict OOP Rules

These rules are strict but excellent for the code you're writing (not necessarily the tests).

- **100 lines per class**
- **5 lines per method**
- **4 parameters maximum per method**

**How this applies:** If you follow this for your `lib/` code, your classes will naturally be small, which usually means your `spec/` files (Mirroring approach) stay small automatically. Your need for splitting specs often indicates your `lib/` classes are large/complex.

#### The RuboCop Defaults (Automated Consensus)

RuboCop is the standard linter. Its defaults represent the "average" agreement of the community.

- **ClassLength:** Max 100 lines (often bumped to 150-200 in real apps)
- **ModuleLength:** Max 100 lines
- **MethodLength:** Max 10 lines
- **RSpec/ExampleLength:** Max 5 lines (statements inside the `it` block). Note: This excludes setup code like `let` or `before`.

#### Practical RSpec Heuristics

**The "Scroll Test"**
- If you have to scroll more than 2 screens to find the `let` definitions that apply to the test you're reading, the file is too long or the context is too nested.

**The "Context Depth"**
- **Ideal:** 2-3 levels of nesting (`describe` -> `context` -> `it`)
- **Max:** 4 levels
- **Too Deep:** 5+ levels. This usually implies you're testing logic variations that should be extracted into a separate class or method.

**For Method-as-File Approach (Split Specs):**
- **Lines per File:** Aim for < 100 lines per method-spec file. If a single method needs 200+ lines of testing, that specific method is likely too complex (Cyclomatic Complexity).
- **Shared Contexts:** Keep your `shared_context` files under 50 lines. If your setup is larger than that, your object graph is likely too coupled.

#### File Naming Conventions

For the **Split Specs** approach used in this gem:

- **Folder names** = Module/Class names (matches `lib/` structure)
- **File names** = Method names or behavior areas
- **Examples:**
  - `lib/omniauth_openid_federation/strategy.rb` → `spec/omniauth_openid_federation/strategy/authorize_uri_spec.rb`
  - `lib/omniauth_openid_federation/access_token.rb` → `spec/omniauth_openid_federation/access_token/resource_request_spec.rb`
  - `lib/omniauth_openid_federation/tasks_helper.rb` → `spec/omniauth_openid_federation/tasks/test_authentication_flow_spec.rb`

**Naming Rules:**
- Use method names for files when testing a single method: `authorize_uri_spec.rb`
- Use behavior names for files when testing multiple methods together: `callback_phase_spec.rb`
- Avoid generic names like `edge_cases_spec.rb`, `coverage_spec.rb`, `additional_spec.rb` - use specific method/behavior names for easy search

### Test Type Selection

#### Unit Specs (`spec/omniauth_openid_federation/`)

- Use for: Library classes, modules, service objects, utility methods
- Test: Public API behavior, error handling, edge cases
- Example: Testing `Jws.sign`, `Jwks::Fetch.run`, `EntityStatement.parse`

### Testing Workflow

1. **Plan First**: Think carefully about what tests should be written for the given scope/feature
2. **Review Existing Tests**: Check existing specs before creating new test data
3. **Isolate Dependencies**: Use mocks/stubs for external services (HTTP, file system, time)
4. **Use WebMock**: Set up WebMock for HTTP calls to external services
5. **Minimal Scope**: Start with essential tests, add edge cases only when specifically requested
6. **DRY Principles**: Review `spec/support/` for existing shared examples and helpers before duplicating code

### The Mocking Policy: Architectural Boundaries Only

To enforce refactoring resistance, strict controls must be placed on the use of Test Doubles (mocks, stubs, spies).

#### 🚫 STRICTLY FORBIDDEN: Internal Mocks

The policy unequivocally prohibits the mocking of internals. This prohibition covers:

1. **Mocking Private/Protected Methods:**
   - Attempts to mock private methods are fundamentally flawed
   - These methods exist solely to organize code; they do not represent a contract
   - If a test mocks a private method, it is coupled to the signature of that method

2. **Partial Mocks (Spies on the SUT):**
   - Creating a real instance of the SUT but overriding one of its methods
   - This creates a "Frankenstein" object that exists only in the test environment

3. **Reflection-Based State Manipulation:**
   - Using reflection to set private fields to bypass validation logic
   - This tests a state that might be unreachable in the actual application

#### ✅ PERMITTED MOCKS: Architectural Boundaries

Mocking is reserved exclusively for **Architectural Boundaries**—the seams where the SUT interacts with systems it does not own or control.

| Boundary Type | Examples | Rationale for Mocking | Preferred Double |
| :--- | :--- | :--- | :--- |
| **Persistence Layer** | Repositories, DAOs | Eliminates dependency on running DB; speed/isolation | Fake (In-Memory) or Stub |
| **External I/O** | HTTP Clients, RPC | Prevents network calls; simulates error states | Mock or Stub |
| **File System** | Disk Access | Decouples tests from slow/stateful disk | Fake (Virtual FS) |
| **System Env** | Time, Randomness | Removes non-determinism | Stub (Fixed Clock) |
| **Eventing** | Kafka, RabbitMQ | Verifies side effects without running broker | Spy (Capture events) |

### The Input Derivation Protocol

When tempted to mock an internal method to "force" code execution, **STOP**. Instead, use the **Input Derivation Protocol**.

#### Protocol Mechanics

Treat the SUT as a logic puzzle. To execute a specific line of code, solve the logical equation defined by the control flow graph leading to it.

1. **Analyze the Logic (Path Predicate Analysis):**
   - Examine the conditional checks (`if`, `guard clauses`)
   - *Example:* `if user.age > 18: ...`

2. **Reverse Engineer the Input:**
   - Determine the initial state that satisfies the predicate
   - *Result:* Input user must have `age >= 19`

3. **Construct Data (The Fixture):**
   - Create a data fixture that naturally satisfies the conditions
   ```ruby
   valid_user = User.new(age: 25, status: 'ACTIVE')
   ```

4. **Execute via Public API:**
   - Pass the constructed input into the public entry point

#### Addressing "Unreachable" Code

If the Input Derivation Protocol fails (no public input can trigger the line), the target code is technically **unreachable** or **dead code**, or it represents a defensive check for a state the system prevents elsewhere.

#### Techniques

- **Basis Path Testing:** Calculate cyclomatic complexity to determine the number of independent paths needed
- **Equivalence Partitioning:** Divide input space into partitions (e.g., Valid vs. Invalid) and test representative values
- **Boundary Value Analysis:** Test edges of partitions (e.g., age 17, 18, 19)

### Test Data Management

#### Test Doubles and Mocks

- Use verifying doubles (`instance_double`, `class_double`) for external dependencies **only**
- Create test data inline for simple cases
- Use factories or builders for complex test data when needed
- **Never mock methods within the class you're testing**

#### Let/Let! Usage

- **`let`**: Lazy evaluation - only creates when accessed; use by default
- **`let!`**: Eager evaluation - creates immediately; use when laziness causes issues
- Keep `let` blocks close to where they're used
- Avoid creating unused data with `let!`

### Shared Contexts and Helpers

- Use `spec/support/` for shared examples, custom matchers, and test helpers
- Create shared contexts for truly shared behavior across multiple spec files
- Scope helpers appropriately using `config.include` by spec type

**For Split Specs Approach:**
- **Shared Contexts:** When using method-as-file approach, create shared contexts to avoid duplicating setup code
- **Keep shared contexts small:** Under 50 lines per shared context file
- **Example structure:**
  ```ruby
  # spec/support/shared_contexts/strategy_helpers.rb
  RSpec.shared_context "strategy helpers" do
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:public_key) { private_key.public_key }
    let(:provider_issuer) { "https://provider.example.com" }
    # ... shared setup
  end

  # spec/omniauth_openid_federation/strategy/authorize_uri_spec.rb
  RSpec.describe OmniAuth::Strategies::OpenIDFederation, "#authorize_uri" do
    include_context "strategy helpers"
    # ... tests
  end
  ```

### Isolation Best Practices

#### When to Isolate

- Expensive or flaky external IO (HTTP, file system) → stub or use WebMock
- Rare/error branches hard to trigger → stub to reach them
- Nondeterminism (random, time, UUIDs) → stub to deterministic values
- Performance in tight unit scopes → replace heavy collaborators

#### When NOT to Isolate

- Simple Ruby operations
- Cheap internal collaborations
- Where integration tests provide clearer coverage

#### Isolation Techniques

- **Verifying Doubles**: Prefer `instance_double(Class)`, `class_double` over plain `double` to catch interface mismatches
- **Stubs**: `allow(obj).to receive(:method).and_return(value)` for replacing behavior
- **Spies**: `expect(obj).to have_received(:method).with(args)` for verifying side effects
- **WebMock**: Stub HTTP requests for external services
- **Time Stubs**: Use `travel_to` or `Timecop` for deterministic time-dependent tests
- **Sequential Returns**: `and_return(value1, value2)` for modeling retries and fallbacks

#### Isolation Rules

1. **Preserve Public Behavior**: Test via public API, never test private methods directly
2. **Mock Only Boundaries**: Only mock external dependencies (HTTP, DB, File System, Time), never internal methods
3. **Scope Narrowly**: Keep stubs local to examples; avoid global state and `allow_any_instance_of`
4. **Use Verifying Doubles**: Prefer `instance_double`, `class_double` over plain doubles
5. **Default to WebMock for HTTP**: Stub HTTP requests to avoid external dependencies
6. **Assert Outcomes**: Focus on behavior, not internal call choreography
7. **Input Derivation**: When you need to test a specific code path, derive the input that naturally triggers it

### WebMock Configuration

- WebMock is configured in `spec/support/webmock.rb`
- Stub HTTP requests to avoid external dependencies in tests
- Use `stub_request` to mock HTTP responses
- Example:

```ruby
stub_request(:get, "https://example.com/.well-known/jwks.json")
  .to_return(status: 200, body: { keys: [] }.to_json)
```

### Testing HTTP Interactions

When testing classes that make HTTP requests:

```ruby
RSpec.describe OmniauthOpenidFederation::Jwks::Fetch do
  let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }
  
  it "fetches JWKS from provider" do
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: { keys: [] }.to_json)
    
    result = described_class.run(jwks_uri)
    expect(result).to be_a(Hash)
  end
end
```

### Testing File Operations

When testing file reading/writing:

```ruby
RSpec.describe OmniauthOpenidFederation::EntityStatementReader do
  let(:temp_file) do
    file = Tempfile.new(["entity_statement", ".jwt"])
    file.write(content)
    file.rewind
    file
  end
  
  after do
    temp_file.close
    temp_file.unlink
  end
  
  it "reads entity statement from file" do
    keys = described_class.fetch_keys(entity_statement_path: temp_file.path)
    expect(keys).to be_an(Array)
  end
end
```

### Testing JWT Operations

When testing JWT signing/verification:

```ruby
RSpec.describe OmniauthOpenidFederation::Jws do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  
  it "signs JWT with private key" do
    jws = described_class.new(
      client_id: "test-client",
      redirect_uri: "https://example.com/callback",
      private_key: private_key
    )
    
    signed_jwt = jws.sign
    expect(signed_jwt.split(".").length).to eq(3) # JWT has 3 parts
  end
end
```

### Testing Error Handling

Always test error cases:

```ruby
it "raises error when private key is missing" do
  jws = described_class.new(
    client_id: "test-client",
    redirect_uri: "https://example.com/callback"
  )
  
  expect { jws.sign }.to raise_error(StandardError, /Private key is REQUIRED/)
end
```

### Code Examples: Anti-Patterns vs. Best Practices

#### 🔴 Bad Practice: Targeted Mocking (Internal Mocks)

**Why it is bad:** It couples the test to `validate_user`. If renamed, the test crashes. The test accepts invalid input because of the mock, creating a false positive.

```ruby
# ❌ DO NOT DO THIS
RSpec.describe OmniauthOpenidFederation::Jws do
  it "signs JWT when validation passes" do
    jws = described_class.new(
      client_id: "test-client",
      redirect_uri: "https://example.com/callback",
      private_key: private_key
    )
    
    # VIOLATION: Mocking a method inside the SUT
    allow(jws).to receive(:validate_private_key!).and_return(true)
    
    # False Negative: The code accepts invalid input because of the mock
    result = jws.sign
    expect(result).to be_present
  end
end
```

#### 🟢 Best Practice: Input Driven

**Why it is good:** It treats the class as a black box. It proves the logic works with valid input.

```ruby
# ✅ DO THIS
RSpec.describe OmniauthOpenidFederation::Jws do
  it "signs JWT with valid private key" do
    # 1. Setup SUT with architectural fakes (if needed)
    # In this case, we use a real private key (no mocking needed)
    
    # 2. Input Derivation: Construct input that NATURALLY passes validation
    valid_private_key = OpenSSL::PKey::RSA.new(2048)
    
    jws = described_class.new(
      client_id: "test-client",
      redirect_uri: "https://example.com/callback",
      private_key: valid_private_key  # Valid input that naturally passes
    )
    
    # 3. Execution via Public API
    result = jws.sign
    
    # 4. Assert Behavior
    expect(result).to be_present
    expect(result.split(".").length).to eq(3)  # Valid JWT structure
  end
end
```

#### 🟢 Best Practice: Boundary Mocking (External Dependencies)

**Why it is good:** Time is an architectural boundary. We control it via dependency injection.

```ruby
# ✅ DO THIS
RSpec.describe OmniauthOpenidFederation::Jws do
  it "includes expiration time in JWT" do
    # 1. Control 'now' via Boundary Stub (if time was injected)
    # In this case, we test the behavior: exp is in the future
    
    jws = described_class.new(
      client_id: "test-client",
      redirect_uri: "https://example.com/callback",
      private_key: private_key
    )
    
    signed_jwt = jws.sign
    payload = JSON.parse(Base64.urlsafe_decode64(signed_jwt.split(".")[1]))
    
    # 2. Assert Behavior: exp claim is in the future
    expect(payload["exp"]).to be > Time.now.to_i
  end
end
```

### Anti-Patterns to Avoid

- **Mocking Internal Methods:** Never mock private/protected methods or methods within the class you're testing
- **Partial Mocks:** Never create partial mocks of the SUT (e.g., `allow(service).to receive(:internal_method)`)
- **Testing Implementation Details:** Don't assert that specific private methods were called
- **Reflection-Based Manipulation:** Don't use reflection to set private fields
- **Not Isolating Boundaries:** Always isolate external dependencies (HTTP, file system, time)
- **Using Real External Services:** Never use real external services in tests
- **Testing Ruby/Gem Functionality:** Don't test features built into Ruby or external gems
- **Over-Testing Edge Cases:** Only test edge cases when specifically requested
- **Creating Unnecessary Data:** Avoid creating unused test data with `let!`
- **Using `allow_any_instance_of`:** Prefer proper dependency injection and stubbing

### Self-Correction Checklist

Before committing, perform this audit:

1. **Ownership Check:** Am I mocking a method that belongs to the class I am testing? (If YES → Delete mock)
2. **Verification Target:** Am I testing that the code works, or how the code works?
3. **Input Integrity:** Did I create the necessary input data to reach the code path naturally?
4. **Refactoring Resilience:** If I rename private helper methods, will this test still pass?
5. **Boundary Check:** Is the mock representing a true I/O boundary (DB, Web, Time)?
6. **Public API:** Am I testing through the public interface only?

### Example Test Structure

```ruby
RSpec.describe OmniauthOpenidFederation::Jwks::Fetch do
  describe ".run" do
    let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }
    
    context "with successful response" do
      it "fetches and returns JWKS" do
        # ✅ Mocking HTTP (architectural boundary) is allowed
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: { keys: [] }.to_json)
        
        # Execute via public API
        result = described_class.run(jwks_uri)
        
        # Assert behavior (what it returns), not implementation
        expect(result).to be_a(Hash)
        expect(result).to have_key(:keys)
      end
    end
    
    context "with HTTP error" do
      it "raises error on failure" do
        # ✅ Mocking HTTP error (architectural boundary)
        stub_request(:get, jwks_uri)
          .to_return(status: 500)
        
        # Assert behavior (error handling)
        expect { described_class.run(jwks_uri) }
          .to raise_error(StandardError, /Failed to fetch JWKS/)
      end
    end
  end
end
```

### Summary: The Refactoring-Resistant Testing Matrix

| Feature | Strict Mocking (Recommended) | Targeted Mocking (Prohibited) |
| :--- | :--- | :--- |
| **Primary Focus** | Public Contract / Behavior | Internal Implementation |
| **Private Methods** | Ignored (Opaque Box) | Mocked / Spied / Tested Directly |
| **Refactoring Safety** | High (Implementation agnostic) | Low (Coupled to structure) |
| **Bug Detection** | High (Verifies logic integration) | Mixed (Misses integration issues) |
| **Maintenance Cost** | Low (Survives changes) | High (Requires updates on refactor) |
| **Architectural Impact** | Encourages Decoupling & DI | Encourages Tightly Coupled Code |

### Code Quality Metrics Summary

#### Target Metrics for This Gem

| Metric | Target | Warning | Critical |
| :--- | :--- | :--- | :--- |
| **Spec file length** | < 100 lines | 100-300 lines | > 300 lines |
| **Example (`it`) length** | < 10 lines | 10-20 lines | > 20 lines |
| **Context nesting depth** | 2-3 levels | 4 levels | 5+ levels |
| **Shared context length** | < 50 lines | 50-100 lines | > 100 lines |
| **Methods per class (lib/)** | < 10 | 10-20 | > 20 |
| **Lines per class (lib/)** | < 100 | 100-300 | > 300 |

#### When to Refactor

- **Split a spec file** when it exceeds 300 lines or requires scrolling > 2 screens to find relevant `let` definitions
- **Extract shared context** when setup code is duplicated across 3+ spec files
- **Split a class** when it exceeds 300 lines or has > 20 methods (applies to `lib/` code)
- **Simplify a test** when an `it` block exceeds 15 lines or tests multiple behaviors
