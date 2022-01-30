#!/usr/bin/env ruby
require 'openssl'
require 'socket'
require 'securerandom'
require 'base64'

print "Program CA (server)\n"

print "Adres IP: "
puts IPSocket.getaddress(Socket.gethostname) # pozyskiwanie adresu IP
print "\n"

print "Generowanie kluczy i certyfikatu CA...\n\n"

root_key = OpenSSL::PKey::RSA.new 2048 # Generowanie klucza publicznego/prywatnego CA
root_ca = OpenSSL::X509::Certificate.new
root_ca.version = 2 
root_ca.serial = 1
root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
root_ca.issuer = root_ca.subject # root CA jest "self-signed"
root_ca.public_key = root_key.public_key
root_ca.not_before = Time.now
root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 lata ważności
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = root_ca
ef.issuer_certificate = root_ca
root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
certyfikatCA = root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

print "Klucz publiczny CA\n"
puts root_key.public_key

print "\nWygenerowano certyfikat CA:\n"
puts certyfikatCA

print "\n\nOczekiwanie na Clienta"

server = TCPServer.open(3000) # Otwarcie serwera na porcie 3000
client = server.accept # Oczekiwanie na Boba (klienta) i akceptacja połączenia 
 
print "\n\nPołączono z nowym Clientem! Odbieranie danych i tworzenie Cetryfikatu...\n\n"

alice_pub_key_string = [client.gets.gsub(/\n$/, '')].pack("B*") # Odebranie klucza publicznego od Clienta
alice_pub_key = OpenSSL::PKey::RSA.new(alice_pub_key_string)

print "Odebrano dane! Sprawdzanie danych i generowanie certyfikatu..."

cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 2
cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby certificate"
cert.issuer = root_ca.subject 
cert.public_key = alice_pub_key
cert.not_before = Time.now
cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 rok ważności
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = root_ca
cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
certyfikatClient = cert.sign(root_key, OpenSSL::Digest::SHA256.new)

print "\n\nWygenerowano i podpisano certyfikat!\n"
puts certyfikatClient

print "\n\nOdsyłanie podpisanego certyfikatu z kluczem publicznym CA...\n\n"

client.puts certyfikatClient.to_pem.unpack("B*") # Wysłanie certyfikatu do Clienta
client.puts root_key.public_key.to_pem.unpack("B*") # Wysłanie klucza publicznego do Clienta

print "Wysłano!\n\n"

server.close
