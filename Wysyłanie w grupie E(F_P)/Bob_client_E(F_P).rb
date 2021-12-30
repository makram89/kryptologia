#!/usr/bin/env ruby
require 'openssl'
require 'socket'
require 'securerandom'
require 'base64'

print "Program Bob (client)\n"

print "Podaj IP Alice (server): "

$ip = gets.chomp # Pozyskanie adresu IP
print "\n"

sock = TCPSocket.new($ip, 3000) # Łączenie z serwerem

ecB = OpenSSL::PKey::EC.new("prime256v1") 
ecB.generate_key! # Generuje pary (x, y) (klucz prywatny i publiczny)

#puts ecB.to_text 
#puts ecB.private_key? 
#puts ecB.public_key?

print "priv_key_Bob="
pvK = ecB.private_key # Klucz prywatny
puts pvK

print "pub_key_Bob=\n"
tempPK = OpenSSL::PKey::EC.new("prime256v1")
tempPK.public_key = ecB.public_key
$pubK = tempPK.to_pem # Klucz publiczny
puts $pubK
print "\n"

pubK_Alice = [sock.gets.gsub(/\n$/, '')].pack("B*") # Odebranie klucza publicznego Alice
sock.puts $pubK.unpack("B*") # Wysłanie klucza publicznego Boba do Alice

print "\nOdebrano klucz publiczny Alice: \n"
puts pubK_Alice

temp = OpenSSL::PKey::EC.new(pubK_Alice)
$key = ecB.dh_compute_key(temp.public_key) # Tworzenie klucza sesyjnego

print "Obliczono klucz sesyjny: "
puts $key

$iv = SecureRandom.random_bytes(16) # Generowanie IV
print "Wygenerowano IV: "
puts $iv
print "\n"

sock.puts $iv.unpack("B*") # Wysłanie IV do Alice

# Szyfrowanie
c = OpenSSL::Cipher::AES.new(256, 'CBC')
  
# Odszyfrowanie
d = OpenSSL::Cipher::AES.new(256, 'CBC')

###

print "Oczekiwanie na wiadomość od Alice...\n\n"

while true

  # Resetowanie i ustawianie deszyfrowania
  d.reset
  d.decrypt
  d.iv = $iv.gsub(/\n$/, '')
  d.key = $key.gsub(/\n$/, '')
  
  # Odbieranie wiadomości
  $message = [sock.gets.gsub(/\n$/, '')].pack("B*") # Odebranie szyfrogramu od Alice
  print "Odebrano szyfrogram od Alice: "
  puts $message
  $decrypted = d.update($message.gsub(/\n$/, '')) + d.final 
  print "\nOdszyfrowano wiadomość: "  
  puts $decrypted
  print "\n"

  # Resetowanie i ustawianie szyfrowania
  c.reset
  c.encrypt
  c.iv = $iv.gsub(/\n$/, '')
  c.key = $key.gsub(/\n$/, '')

  # Wysyłanie wiadomości
  print "Wiadomość do Alice: "
  $message = gets.chomp # Wiadomość do Alice
  $encrypted = c.update($message) + c.final # Szyfrowanie
  sock.puts $encrypted.unpack("B*") # Wysłanie szyfrogramu do Alice
  print "Wygenerowano i wysłano szyfrogram do Boba: "
  puts $encrypted

  print "\n\nOczekiwanie na odpowiedź...\n\n"
  
end

sock.close
  

