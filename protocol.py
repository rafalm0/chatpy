from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP


class ProtocolMessage:

    def __init__(self):
        chave = RSA.generate(2048, e=65537)

        self.msgType = ''
        self.msgLength = 0
        self.msgValue = ''
        self.private_key = chave.exportKey("PEM")
        self.public_key = chave.publickey().exportKey("PEM")
        self.AES_key = None
        self.other_key = None

    def encode(self):
        # TODO fazer criptografia aqui ó

        cipher = AES.new(self.AES_key, AES.MODE_EAX, nonce=b'poiuytrewqasdfgh')
        ciphertext, tag = cipher.encrypt_and_digest(f'{self.msgType} {self.msgValue}'.encode('utf8'))

        return ciphertext

    def decode_input(self, data):
        cipher = AES.new(self.AES_key, AES.MODE_EAX, nonce=b'poiuytrewqasdfgh')
        msg = cipher.decrypt(data).decode('utf-8')
        self.msgType = msg[0:4]
        self.msgLength = len(data)
        self.msgValue = msg[5:]

    def decode_raw(self, data):
        msg = data.decode('utf-8')
        self.msgType = msg[0:4]
        self.msgLength = len(data)
        self.msgValue = msg[5:]

    def encode_raw(self):
        return f'{self.msgType} {self.msgValue}'.encode('utf8')

    def encode_rsa(self):
        publ = PKCS1_OAEP.new(RSA.import_key(self.other_key))
        return publ.encrypt(f'{self.msgType} {self.msgValue}'.encode('utf8'))

    def decode_rsa(self, data):
        priv = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        self.decode_raw(priv.decrypt(data))

    def quick_send(self, command, message='', connection=False):
        if not connection:
            if command.lower() in ['retr', 'clos']:
                self.manual_input(command.lower().ljust(4), 5)
            else:
                self.manual_input(command.lower().ljust(4), 5 + len(message.encode('utf-8')), message)
        else:
            if command.lower() in ['retr', 'clos']:
                self.manual_input(command.lower().ljust(4), 5)
            else:
                self.manual_input(command.lower().ljust(4), 5 + len(message), message.decode('utf-8'))
    def manual_input(self, msgType, msgLength=0, msgValue=''):
        self.msgType = msgType
        self.msgLength = msgLength
        self.msgValue = msgValue

    def __repr__(self):
        return f'{self.msgType} {self.msgValue}'


def read_incoming(received):
    x = ProtocolMessage()
    x.decode(received)
    return x


def prepare_to_send(command, message=''):
    if command.lower() in ['retr', 'clos']:
        x = ProtocolMessage(command.lower().ljust(4), 5)
    else:
        x = ProtocolMessage(command.lower().ljust(4), 5 + len(message.encode('utf-8')), message)
    return x
