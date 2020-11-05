from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP

chave = RSA.generate(2048, e=65537)
chave2 = RSA.generate(2048, e=65537)

AES_key = b'poiuytrewqasdfgh'

private_key1 = RSA.import_key(chave.exportKey("PEM"))
public_key1 = RSA.import_key(chave.publickey().exportKey("PEM"))

private_key2 = RSA.import_key(chave2.exportKey("PEM"))
public_key2 = RSA.import_key(chave2.publickey().exportKey("PEM"))


texto = 'poiuytrewqasdfgh'.encode('utf-8')

priv_1 = PKCS1_OAEP.new(private_key1)
pub_1 = PKCS1_OAEP.new(public_key1)

priv_2 = PKCS1_OAEP.new(private_key2)
pub_2 = PKCS1_OAEP.new(public_key2)


tex_1a = pub_1.encrypt(texto)
tex_2a = pub_2.encrypt(tex_1a)
tex_1b = priv_1.decrypt(tex_2a)
tex_2b = priv_2.decrypt(tex_1b)


print(tex_2b.decode('utf-8'))
pass