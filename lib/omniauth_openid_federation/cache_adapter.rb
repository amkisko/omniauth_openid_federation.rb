# Cache adapter interface for framework-agnostic caching
# Provides a simple interface that can be implemented by any cache backend
#
# @example Using Rails cache (automatic)
#   # Rails.cache is automatically detected and used if available
#
# @example Using a custom cache adapter
#   class MyCacheAdapter
#     def fetch(key, expires_in: nil)
#       # Your cache implementation
#       yield if block_given?
#     end
#
#     def read(key)
#       # Your cache read implementation
#     end
#
#     def write(key, value, expires_in: nil)
#       # Your cache write implementation
#     end
#
#     def delete(key)
#       # Your cache delete implementation
#     end
#   end
#
#   OmniauthOpenidFederation.configure do |config|
#     config.cache_adapter = MyCacheAdapter.new
#   end
module OmniauthOpenidFederation
  class CacheAdapter
    class << self
      attr_writer :adapter

      # Get the configured cache adapter
      # Automatically detects Rails.cache if available
      #
      # @return [Object, nil] Cache adapter instance or nil if no cache available
      def adapter
        @adapter ||= detect_adapter
      end

      # Reset the cache adapter (useful for testing)
      # Forces re-detection of cache adapter on next access
      #
      # @return [void]
      def reset!
        @adapter = nil
      end

      # Check if caching is available
      #
      # @return [Boolean] true if cache adapter is available
      def available?
        !adapter.nil?
      end

      # Fetch a value from cache, or compute and cache it
      #
      # @param key [String] Cache key
      # @param expires_in [Integer, nil] Expiration time in seconds (nil = no expiration)
      # @yield Block to compute value if not cached
      # @return [Object] Cached or computed value
      def fetch(key, expires_in: nil, &block)
        return yield unless available? && block_given?

        adapter.fetch(key, expires_in: expires_in, &block)
      end

      # Read a value from cache
      #
      # @param key [String] Cache key
      # @return [Object, nil] Cached value or nil
      def read(key)
        return nil unless available?
        adapter.read(key)
      end

      # Write a value to cache
      #
      # @param key [String] Cache key
      # @param value [Object] Value to cache
      # @param expires_in [Integer, nil] Expiration time in seconds (nil = no expiration)
      # @return [void]
      def write(key, value, expires_in: nil)
        return unless available?
        adapter.write(key, value, expires_in: expires_in)
      end

      # Delete a value from cache
      #
      # @param key [String] Cache key
      # @return [void]
      def delete(key)
        return unless available?
        adapter.delete(key)
      end

      # Clear all cache (if supported)
      #
      # @return [void]
      def clear
        return unless available?
        adapter.clear if adapter.respond_to?(:clear)
      end

      private

      # Detect and return the appropriate cache adapter
      #
      # @return [Object, nil] Cache adapter instance or nil
      def detect_adapter
        # Use configured adapter from configuration if set
        config = OmniauthOpenidFederation::Configuration.config
        if config.cache_adapter
          return config.cache_adapter
        end

        # Try Rails cache
        if defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache
          return RailsCacheAdapter.new(Rails.cache)
        end

        # Try ActiveSupport::Cache if available (without Rails)
        if defined?(ActiveSupport::Cache::Store)
          # Try to use a memory store as fallback
          begin
            require "active_support/cache/memory_store"
            return RailsCacheAdapter.new(ActiveSupport::Cache::MemoryStore.new)
          rescue LoadError
            # ActiveSupport::Cache::MemoryStore not available
          end
        end

        nil
      end
    end

    # Adapter for Rails/ActiveSupport cache stores
    # Wraps Rails.cache or ActiveSupport::Cache::Store to provide consistent interface
    class RailsCacheAdapter
      def initialize(cache_store)
        @cache_store = cache_store
      end

      def fetch(key, expires_in: nil, &block)
        options = {}
        options[:expires_in] = expires_in if expires_in
        # Handle nil key gracefully
        return block.call if key.nil? && block_given?
        @cache_store.fetch(key, options, &block)
      end

      def read(key)
        @cache_store.read(key)
      end

      def write(key, value, expires_in: nil)
        options = {}
        options[:expires_in] = expires_in if expires_in
        @cache_store.write(key, value, options)
      end

      def delete(key)
        @cache_store.delete(key)
      end

      def clear
        @cache_store.clear if @cache_store.respond_to?(:clear)
      end
    end
  end
end
