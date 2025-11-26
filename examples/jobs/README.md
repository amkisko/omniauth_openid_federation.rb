# Background Job Examples for Federation Endpoints

This directory contains example background jobs for generating and caching federation files.

## Jobs

### 1. FederationFilesGenerationJob

**Purpose**: Generate and cache federation files (entity statement, JWKS) to disk.

**When to use**:
- Periodic generation (daily, weekly)
- After key rotation
- Before deployment
- To ensure files are always available

**What it does**:
- Generates `config/.federation-entity-statement.jwt`
- Generates `config/.federation-jwks.json`
- Clears Rails cache for federation endpoints

**Usage**:
```ruby
# Schedule in config/schedule.rb (whenever gem)
every 1.day, at: '2:00 am' do
  runner 'FederationFilesGenerationJob.perform_later'
end

# Or call manually
FederationFilesGenerationJob.perform_later
```

### 2. FederationCacheRefreshJob

**Purpose**: Refresh cached federation data without generating files.

**When to use**:
- Periodic cache refresh (hourly, daily)
- After key rotation
- When configuration changes
- To pre-warm caches

**What it does**:
- Clears all federation-related Rails caches
- Optionally pre-warms caches for immediate availability

**Usage**:
```ruby
# Schedule in config/schedule.rb (whenever gem)
every 1.hour do
  runner 'FederationCacheRefreshJob.perform_later'
end

# Or call manually after key rotation
FederationCacheRefreshJob.perform_later
```

## Setup Instructions

### Step 1: Copy Job Files

Copy the example job files to your `app/jobs/` directory:

```bash
cp examples/jobs/federation_files_generation_job.rb.example app/jobs/federation_files_generation_job.rb
cp examples/jobs/federation_cache_refresh_job.rb.example app/jobs/federation_cache_refresh_job.rb
```

### Step 2: Configure Scheduling

Add to `config/schedule.rb` (if using whenever gem):

```ruby
# Generate federation files daily at 2 AM
every 1.day, at: '2:00 am' do
  runner 'FederationFilesGenerationJob.perform_later'
end

# Refresh caches hourly
every 1.hour do
  runner 'FederationCacheRefreshJob.perform_later'
end
```

Or use cron directly:

```bash
# Generate files daily at 2 AM
0 2 * * * cd /path/to/app && bin/rails runner 'FederationFilesGenerationJob.perform_now'

# Refresh caches hourly
0 * * * * cd /path/to/app && bin/rails runner 'FederationCacheRefreshJob.perform_now'
```

### Step 3: Test Jobs

Test the jobs manually:

```bash
# Test file generation
bin/rails runner 'FederationFilesGenerationJob.perform_now'

# Test cache refresh
bin/rails runner 'FederationCacheRefreshJob.perform_now'
```

## When to Use Each Job

### Use FederationFilesGenerationJob when:
- ✅ You want files on disk for backup/recovery
- ✅ You want to serve from files instead of generating on-demand
- ✅ You need files for external tools or scripts
- ✅ You want to version control generated files (not recommended for production)

### Use FederationCacheRefreshJob when:
- ✅ You only need in-memory caching (Rails.cache)
- ✅ You want to refresh caches without generating files
- ✅ You want faster cache refresh cycles
- ✅ You don't need files on disk

### Use Both when:
- ✅ You want both file generation and cache refresh
- ✅ You want redundancy (files + cache)
- ✅ You have different refresh cycles for files vs cache

## Key Rotation Workflow

When rotating keys:

1. **Before rotation**: Generate new files with new keys
   ```bash
   bin/rails runner 'FederationFilesGenerationJob.perform_now'
   ```

2. **After rotation**: Refresh caches
   ```bash
   bin/rails runner 'FederationCacheRefreshJob.perform_now'
   ```

3. **Verify**: Check that endpoints return new keys
   ```bash
   curl https://your-app.com/.well-known/jwks.json
   curl https://your-app.com/.well-known/signed-jwks.json
   ```

## Monitoring

Monitor job execution:

```ruby
# In your monitoring system
FederationFilesGenerationJob.perform_later
# Check logs for success/failure

# Or use ActiveJob monitoring
# Check GoodJob dashboard or similar
```

## Error Handling

Both jobs include error handling:
- Logs errors to Rails.logger
- Raises exceptions for job retry (if configured)
- Continues execution even if one step fails (where appropriate)

## Performance Considerations

- **File Generation**: Takes longer (file I/O), but files persist
- **Cache Refresh**: Faster (in-memory), but data is ephemeral
- **Pre-warming**: Optional, ensures data is ready immediately

## Security Considerations

- Generated files contain public keys only (safe to store)
- Entity statement files are signed JWTs (safe to store)
- Private keys are never written to files
- Files should be in `config/` directory (not publicly accessible)

## Troubleshooting

### Job fails with "Federation endpoint not configured"
- Ensure `FederationEndpoint.configure` is called in initializer
- Check that all required configuration is set

### Files not generated
- Check write permissions on `config/` directory
- Check Rails.logger for error messages
- Verify configuration is valid

### Cache not refreshing
- Check that Rails.cache is configured
- Verify cache keys match expected patterns
- Check cache TTL settings

