#!/usr/bin/env ruby
require 'openssl'
require 'socket'
require 'securerandom'
require 'base64'

print "Program Alice (client)\n"
print "Generowanie kluczy...\n\n"

key = OpenSSL::PKey::RSA.new 2048
$public_key = key.public_key

print "Wygenerowano klucze! \nKlucz publiczny Alice:\n"
puts $public_key

print "\n\nPodaj IP CA (server): "

$ip = gets.chomp # Pozyskanie adresu IP
print "\n"

sock = TCPSocket.new($ip, 3000) # Łączenie z serwerem

print "Połączono z serwerem CA! Przesyłanie wymaganych danych do certyfikatu"

sock.puts key.public_key.to_pem.unpack("B*") # Wysłanie klucza publicznego Alice do CA

print "\n\nDane przesłane! Oczekiwanie na odpowiedź CA...\n\n"

$certyfikat = [sock.gets.gsub(/\n$/, '')].pack("B*") # Odebranie certyfikatu od CA
$kluczPublicznyCA = [sock.gets.gsub(/\n$/, '')].pack("B*") # Odebranie certyfikatu od CA

print "Odebrano certyfikat i klucz publiczny CA:\n"
puts $certyfikat
print "\n\n"
puts $kluczPublicznyCA

print "\n\n"

sock.close
  

