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

pk_to_der = [sock.gets.gsub(/\n$/, '')].pack("B*") # Odebranie pk.to_der od Alice

dhB = OpenSSL::PKey::DH.new(pk_to_der) # Generuje (p,g) p=2q+1 p prime -safe prome

#p = dhB.p
#g = dhB.g

#print "p="
#puts p

#print "g="
#puts g

dhB.generate_key! # Generuje na podstawie (p,g) pare (x, y) (klucz prywatny i publiczny)

print "priv_key_Bob="
pvK = dhB.priv_key # Klucz prywatny
puts pvK

print "pub_key_Bob="
pubK = dhB.pub_key # Klucz publiczny
puts pubK
print "\n"

pubK_Alice = [sock.gets].to_a[0].gsub(/\n$/, '').to_i # Odebranie klucza publicznego Alice
sock.puts pubK # Wysłanie klucza publicznego Boba do Alice

print "Odebrano klucz publiczny Alice: "
puts pubK_Alice

$key = dhB.compute_key(pubK_Alice) # Tworzenie klucza sesyjnego

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
  

