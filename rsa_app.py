from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time

# Citim parola din fisier
with open("parola.txt", "r", encoding="utf-8") as f:
    parola = f.read().strip()

# Generăm cheile RSA
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("cheie_privata.pem", "wb") as f:
    f.write(private_key)

with open("cheie_publica.pem", "wb") as f:
    f.write(public_key)

# Criptăm parola
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))

start_encrypt = time.time()
encrypted = cipher_rsa.encrypt(parola.encode())
end_encrypt = time.time()

with open("parola_criptata.bin", "wb") as f:
    f.write(encrypted)

# Decriptăm parola
cipher_rsa_dec = PKCS1_OAEP.new(RSA.import_key(private_key))

start_decrypt = time.time()
decrypted = cipher_rsa_dec.decrypt(encrypted)
end_decrypt = time.time()

with open("parola_decriptata.txt", "w", encoding="utf-8") as f:
    f.write(decrypted.decode())

# Salvăm timpii de execuție
with open("timp_executie.txt", "w", encoding="utf-8") as f:
    f.write(f"Timp criptare: {end_encrypt - start_encrypt:.6f} secunde\n")
    f.write(f"Timp decriptare: {end_decrypt - start_decrypt:.6f} secunde")
