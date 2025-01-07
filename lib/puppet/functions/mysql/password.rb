# frozen_string_literal: true

require 'digest/sha1'
require 'digest/sha2'
require 'securerandom'

# @summary
#   Hash a string as mysql's "PASSWORD()" function or the "caching_sha2_password" plugin
#   would do it.
#
Puppet::Functions.create_function(:'mysql::password') do
  # @param password
  #   Plain text password.
  # @param sensitive
  #   If the mysql password hash should be of datatype Sensitive[String]
  #
  # @return hash
  #   The mysql password hash from the clear text password.
  #
  dispatch :password do
    required_param 'Variant[String, Sensitive[String]]', :password
    optional_param 'Boolean', :sensitive
    return_type 'Variant[String, Sensitive[String]]'
  end

  def password(password, sensitive = false)
    password = password.unwrap if password.is_a?(Puppet::Pops::Types::PSensitiveType::Sensitive)

    # This magic string is the hex encoded form of `$A$005${SALT}{SHA DIGEST}`, matching MySQL's expected format
    result_string = if %r{\*[A-F0-9]{40}$}.match?(password) || # SHA1
                      %r{\$A\$\d{3}\$[A-Za-z0-9./]{20}[A-Za-z0-9./]{43}$}.match?(password) # SHA256
                      password
                    elsif password.empty?
                      ''
                    else
                      generate_hash(password)
                    end

    if sensitive
      Puppet::Pops::Types::PSensitiveType::Sensitive.new(result_string)
    else
      result_string
    end
  end
  private

  def generate_hash(password)
    if @plugin == 'caching_sha2_password'
      salt = SecureRandom.hex(10)[0, 20]  # Generate 20 hex characters (10 bytes)
      mysql_sha256_password_hash(password, salt)
    else
      "*#{Digest::SHA1.hexdigest(Digest::SHA1.digest(password)).upcase}"
    end
  end

  def mysql_sha256_password_hash(password, salt)
    count = 5
    iteration = 1000 * count
    digest = sha256_digest(password, salt, iteration)
    "$A$#{count.to_s.rjust(3, '0')}$#{salt}#{digest}"
  end

  # This is a translation of the python code from this ansible module:
  # https://github.com/ansible-collections/community.mysql/pull/631/

  def sha256_digest(key, salt, loops)
    num_bytes = 32
    bytes_key = key.encode('ASCII-8BIT')
    bytes_salt = salt.encode('ASCII-8BIT')
    digest_b = hash_sha256(bytes_key + bytes_salt + bytes_key)
  
    tmp = bytes_key + bytes_salt
    (bytes_key.length).downto(1) do |i|
      tmp += i > num_bytes ? digest_b : digest_b[0, i]
    end
  
    i = bytes_key.length
    while i > 0
      tmp += (i & 1 != 0) ? digest_b : bytes_key
      i >>= 1
    end
  
    digest_a = hash_sha256(tmp)
  
    tmp = bytes_key * bytes_key.length
    digest_dp = hash_sha256(tmp)
  
    byte_sequence_p = ''
    (bytes_key.length).downto(1) do |i|
      byte_sequence_p += i > num_bytes ? digest_dp : digest_dp[0, i]
    end
  
    tmp = bytes_salt * (16 + digest_a.getbyte(0))
    digest_ds = hash_sha256(tmp)
  
    byte_sequence_s = ''
    (bytes_salt.length).downto(1) do |i|
      byte_sequence_s += i > num_bytes ? digest_ds : digest_ds[0, i]
    end
  
    digest_c = digest_a
  
    loops.times do |i|
      tmp = (i & 1 != 0) ? byte_sequence_p : digest_c
      tmp += byte_sequence_s if i % 3 != 0
      tmp += byte_sequence_p if i % 7 != 0
      tmp += (i & 1 != 0) ? digest_c : byte_sequence_p
      digest_c = hash_sha256(tmp)
    end
  
    inc1, inc2, mod, ending = 10, 21, 30, 0
    i = 0
    tmp = ''
  
    loop do
      tmp += to64(
        (digest_c.getbyte(i) << 16) |
        (digest_c.getbyte((i + inc1) % mod) << 8) |
        digest_c.getbyte((i + inc1 * 2) % mod),
        4
      )
      i = (i + inc2) % mod
      break if i == ending
    end
  
    tmp += to64((digest_c.getbyte(31) << 8) | digest_c.getbyte(30), 3)
    tmp
  end

  def to64(v, n)
    i64 = ['.', '/'] + (48..57).map(&:chr) + (65..90).map(&:chr) + (97..122).map(&:chr)
    result = ''
    while n > 0
      n -= 1
      result += i64[v & 0x3F]
      v >>= 6
    end
    result
  end

  def hash_sha256(data)
    Digest::SHA256.digest(data)
  end
end
