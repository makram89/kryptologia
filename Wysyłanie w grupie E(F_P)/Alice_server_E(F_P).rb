#!/usr/bin/env ruby
require 'openssl'
require 'socket'

print "Program Alice (server + client)\n"

print "Adres IP: "
puts IPSocket.getaddress(Socket.gethostname) # pozyskiwanie adresu IP
print "\n"
 
server = TCPServer.open(3000) # Otwarcie serwera na porcie 3000
client = server.accept # Oczekiwanie na Boba (klienta) i akceptacja połączenia 
 
ecA = OpenSSL::PKey::EC.new("prime256v1")

#puts ecA.group.curve_name 

#puts ecA.group.order 
#puts ecA.group.to_text

ecA.generate_key! # Generuje pary (x, y) (klucz prywatny i publiczny)

#puts ecA.to_text 
#puts ecA.to_der 
#puts ecA.to_pem 
#puts ecA.private_key? 
#puts ecA.public_key? 

print "priv_key_Alice="
pvK = ecA.private_key # Klucz prywatny
puts pvK

print "pub_key_Alice=\n"
tempPK = OpenSSL::PKey::EC.new("prime256v1")
tempPK.public_key = ecA.public_key
$pubK = tempPK.to_pem # Klucz publiczny
puts $pubK

client.puts $pubK.unpack("B*") # Wysłanie klucza publicznego Alice do Boba
pubK_Bob = [client.gets.gsub(/\n$/, '')].pack("B*") # Odebranie klucza publicznego Alice

print "\nOdebrano klucz publiczny Boba: \n"
puts pubK_Bob
  
temp = OpenSSL::PKey::EC.new(pubK_Bob)
$key = ecA.dh_compute_key(temp.public_key) # Tworzenie klucza sesyjnego

print "Obliczono klucz sesyjny: "
puts $key
  
$iv = [client.gets.gsub(/\n$/, '')].pack("B*") # Odebranie IV od Boba
print "Otrzymano IV: "
puts $iv # Wysłanie IV do Alice
print "\n"
 
# Szyfrowanie
c = OpenSSL::Cipher::AES.new(256, 'CBC')
  
# Odszyfrowanie
d = OpenSSL::Cipher::AES.new(256, 'CBC')

###

while true

  # Resetowanie i ustawianie szyfrowania
  c.reset
  c.encrypt
  c.iv = $iv.gsub(/\n$/, '')
  c.key = $key.gsub(/\n$/, '')

  # Wysyłanie wiadomości
  print "Wiadomość do Boba: "
  $message = gets.chomp # Wiadomość do Bob'a
  $encrypted = c.update($message) + c.final # Szyfrowanie
  client.puts $encrypted.unpack("B*") # Wysłanie szyfrogramu do Boba
  print "Wygenerowano i wysłano szyfrogram do Boba: "
  puts $encrypted

  print "\n\nOczekiwanie na odpowiedź...\n\n"
  
  # Resetowanie i ustawianie deszyfrowania
  d.reset
  d.decrypt
  d.iv = $iv.gsub(/\n$/, '')
  d.key = $key.gsub(/\n$/, '')
  
  # Odbieranie wiadomości
  $message = [client.gets.gsub(/\n$/, '')].pack("B*") # Odebranie szyfrogramu od Boba
  print "Odebrano szyfrogram od Boba: "
  puts $message
  $decrypted = d.update($message.gsub(/\n$/, '')) + d.final
  print "\nOdszyfrowano wiadomość: "  
  puts $decrypted
  print "\n"

end

server.close
