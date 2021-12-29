#!/usr/bin/env ruby
require 'openssl'
require 'socket'

print "Program Alice (server + client)\n"

print "Adres IP: "
puts IPSocket.getaddress(Socket.gethostname) # pozyskiwanie adresu IP
print "\n"
 
server = TCPServer.open(3000) # Otwarcie serwera na porcie 3000
client = server.accept # Oczekiwanie na Boba (klienta) i akceptacja połączenia 
 
dhA = OpenSSL::PKey::DH.new(256) # Generuje (p,g) p=2q+1 p prime -safe prome
pk = dhA.public_key # Klucz publiczny (ogólnie dostępny)
client.puts pk.to_der.unpack("B*") # Wysłanie pk.to_der do Boba
  
#p = pk.p
#g = pk.g

#print "p="
#puts p

#print "g="
#puts g
  
pk.generate_key! # Generuje na podstawie (p,g) pare (x, y) (klucz prywatny i publiczny)

print "pk_priv_key_Alice="
pvK = pk.priv_key # Klucz prywatny
puts pvK

print "pk_pub_key_Alice="
pubK = pk.pub_key # Klucz publiczny
puts pubK
  
print "dh_pub_key_Alice="
pubK = pk.pub_key # Klucz publiczny dh
puts dhA.pub_key
print "\n"

client.puts dhA.pub_key # Wysłanie klucza publicznego Alice do Boba
pubK_Bob = [client.gets].to_a[0].gsub(/\n$/, '').to_i # Odebranie klucza publicznego Boba
  
print "Odebrano klucz publiczny Boba: "
puts pubK_Bob
  
$key = dhA.compute_key(pubK_Bob) # Tworzenie klucza sesyjnego

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
