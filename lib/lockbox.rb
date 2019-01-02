# dependencies
require "openssl"
require "securerandom"

# modules
require "lockbox/box"
require "lockbox/utils"
require "lockbox/version"

# integrations
require "lockbox/carrier_wave_extensions" if defined?(CarrierWave)
require "lockbox/railtie" if defined?(Rails)

class Lockbox
  class Error < StandardError; end
  class DecryptionError < Error; end

  class << self
    attr_accessor :default_options
  end
  self.default_options = {algorithm: "aes-gcm"}

  def initialize(key: nil, algorithm: nil, previous_versions: nil)
    default_options = self.class.default_options
    key ||= default_options[:key]
    algorithm ||= default_options[:algorithm]
    previous_versions ||= default_options[:previous_versions]

    @boxes =
      [Box.new(key, algorithm: algorithm)] +
      Array(previous_versions).map { |v| Box.new(v[:key], algorithm: v[:algorithm]) }
  end

  def encrypt(*args)
    @boxes.first.encrypt(*args)
  end

  def decrypt(ciphertext, **options)
    raise TypeError, "can't convert ciphertext to string" unless ciphertext.respond_to?(:to_str)

    # ensure binary
    ciphertext = ciphertext.to_str
    if ciphertext.encoding != Encoding::BINARY
      # dup to prevent mutation
      ciphertext = ciphertext.dup.force_encoding(Encoding::BINARY)
    end

    @boxes.each_with_index do |box, i|
      begin
        return box.decrypt(ciphertext, **options)
      rescue DecryptionError, RbNaCl::LengthError, RbNaCl::CryptoError
        raise DecryptionError, "Decryption failed" if i == @boxes.size - 1
      end
    end
  end
end