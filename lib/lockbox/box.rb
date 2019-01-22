require "securerandom"

class Lockbox
  class Box
    def initialize(key: nil, algorithm: nil, public_key: nil, private_key: nil)
      raise ArgumentError, "Missing key" unless key || public_key || private_key
      raise ArgumentError, "Cannot pass both key and public/private key" if key && (public_key || private_key)

      key = decode_key(key) if key
      public_key = decode_key(public_key) if public_key
      private_key = decode_key(private_key) if private_key

      algorithm = "x25519xsalsa20" if public_key || private_key
      algorithm ||= "aes-gcm"

      case algorithm
      when "aes-gcm"
        require "lockbox/aes_gcm"
        @box = AES_GCM.new(key)
      when "xchacha20"
        require "rbnacl"
        @box = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
      when "x25519xsalsa20"
        require "rbnacl"
        @box = RbNaCl::Boxes::Sealed.new(public_key, private_key)
      else
        raise ArgumentError, "Unknown algorithm: #{algorithm}"
      end

      @algorithm = algorithm
    end

    def encrypt(message, associated_data: nil)
      if @algorithm == "x25519xsalsa20"
        raise ArgumentError, "Associated data not supported with this algorithm" if associated_data
        @box.encrypt(message)
      else
        nonce = generate_nonce
        ciphertext = @box.encrypt(nonce, message, associated_data)
        nonce + ciphertext
      end
    end

    def decrypt(ciphertext, associated_data: nil)
      if @algorithm == "x25519xsalsa20"
        raise ArgumentError, "Associated data not supported with this algorithm" if associated_data
        @box.decrypt(ciphertext)
      else
        nonce, ciphertext = extract_nonce(ciphertext)
        @box.decrypt(nonce, ciphertext, associated_data)
      end
    end

    # protect key for xchacha20 and x25519xsalsa20
    def inspect
      to_s
    end

    private

    def nonce_bytes
      @box.nonce_bytes
    end

    def generate_nonce
      SecureRandom.random_bytes(nonce_bytes)
    end

    def extract_nonce(bytes)
      nonce = bytes.slice(0, nonce_bytes)
      [nonce, bytes.slice(nonce_bytes..-1)]
    end

    # decode hex key
    def decode_key(key)
      if key.encoding != Encoding::BINARY && key =~ /\A[0-9a-f]{64}\z/i
        key = [key].pack("H*")
      end
      key
    end
  end
end
