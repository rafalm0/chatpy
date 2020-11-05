import protocol as cp

from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM


# erro 001 = usuario nao existente
# erro 002 = senha errada
# erro 003 = sem usuario para checar senha
# erro 004 = usuario nao logado
# erro 005 = usuario nao encontrado
# erro 006 = primeira mensagem precisa ser chave publica
# erro 007 = necessario estabelecer chave AES
class ServerHandler(Thread):

    def __init__(self, host, port):
        Thread.__init__(self)
        self.host = host
        self.port = port
        self.connections = []
        self.active = True
        self.users = {'bruno': '5',
                      'joao': '4',
                      'maria': '3',
                      'rafael': '1',
                      'rubens': '2'}

    def stop(self):
        self.active = False

    def check_username(self, username):
        if username.strip() in self.users.keys():
            return True
        else:
            return False

    def check_password(self, username, password):
        if self.users[username] == password.strip():
            return True
        else:
            return False

    def get_user_from_addr(self, addr):
        for client in self.connections:
            if client.addr == addr:
                return client.username
        return None

    def brod(self, msg, from_addr):
        for client in self.connections:
            if client.addr != from_addr:
                client.conn.sendall(msg.encode())

    def retrive_all_connections(self, from_addr):
        data = ''
        for client in self.connections:
            if client.addr != from_addr:
                data += f'{client.username} : {client.addr}\n'
        return data

    def close_conn(self):
        return

    def priv(self, data, from_user):
        to_user = data.msgValue.split(' ')[0]
        for client in self.connections:
            if client.username == to_user:
                data.prepare_to_send('priv', f'({from_user}): {" ".join(data.msgValue.split(" ")[1:])}')
                client.conn.sendall(data.encode())
                return True
        return False  # nao achou para quem mandar

    def run(self):
        with socket(AF_INET, SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(5)

            while self.active:
                print(f'Waiting for new connections...')

                conn, addr = s.accept()

                ch = ConnectionHandler(conn, addr, self)
                self.connections.append(ch)
                ch.start()

            # Adicionar o código solicitando o fechamento das conexões com os clientes!


class ConnectionHandler(Thread):

    def __init__(self, conn, addr, callback):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.callback = callback
        self.active = True
        self.logged = False
        self.username = ''
        self.password = ''
        self.tent = 0
        self.cripto = False

    def close_conn(self):
        return

    def run(self):
        print(f'O cliente {self.addr} foi conectado!\n')

        cp_1 = cp.ProtocolMessage()
        with self.conn:
            while self.active:
                data = self.conn.recv(4096)
                if not self.cripto:
                    cp_1.decode_raw(data)
                else:
                    if cp_1.AES_key is None:
                        cp_1.decode_rsa(data)
                    else:
                        cp_1.decode_input(data)
                if cp_1.AES_key is not None:
                    if cp_1.msgType == 'user':
                        if self.callback.check_username(cp_1.msgValue):
                            self.username = cp_1.msgValue
                            print(f'O cliente {self.addr} conectou como {self.username}!\n')
                            cp_1.quick_send('ok')
                            self.conn.sendall(cp_1.encode())
                        else:
                            cp_1.quick_send('err', message='001')  # usuario nao existente
                            self.conn.sendall(cp_1.encode())

                    elif cp_1.msgType == 'pass':
                        if self.username == '':
                            cp_1.quick_send('err', message='003')  # nao tinha usuario ainda
                            self.conn.sendall(cp_1.encode())

                        if self.callback.check_password(self.username, cp_1.msgValue):
                            self.password = cp_1.msgValue
                            self.logged = True
                            print(f'O cliente {self.addr} conectado como {self.username} logou com sucesso!\n')
                            cp_1.quick_send('ok')
                            self.conn.sendall(cp_1.encode())
                        else:
                            cp_1.quick_send('err', message='002')  # senha errada
                            self.conn.sendall(cp_1.encode())

                    elif cp_1.msgType == 'mesg':
                        if self.logged:
                            cp_1.quick_send('brod', self.username + ' ' + cp_1.msgValue)
                            self.callback.brod(cp_1, self.addr)
                            print(f'O cliente {self.addr} mandou um texto broadcast : {cp_1.msgValue}\n')
                        else:
                            cp_1.quick_send('err', message='004')  # usuario nao logado
                            self.conn.sendall(cp_1.encode())

                    elif cp_1.msgType == 'retr':
                        if self.logged:
                            msg = self.callback.retrive_all_connections(self.addr)
                            cp_1.quick_send('ok', message=msg)
                            self.conn.sendall(cp_1.encode())
                        else:
                            cp_1.quick_send('err', message='004')  # usuario nao logado
                            self.conn.sendall(cp_1.encode())

                    elif cp_1.msgType == 'priv':
                        if self.logged:
                            if self.callback.priv(cp_1, self.username):
                                pass
                            else:
                                cp_1.quick_send('err', message='005')  # usuario nao encontrado
                                self.conn.sendall(cp_1.encode())
                        else:
                            cp_1.quick_send('err', message='004')  # usuario nao logado
                            self.conn.sendall(cp_1.encode())

                    elif cp_1.msgType == 'brod':
                        if self.logged:
                            ...
                        else:
                            cp_1.quick_send('err', message='004')  # usuario nao logado
                            self.conn.sendall(cp_1.encode())

                    elif cp_1.msgType == 'clos':
                        print(f'O cliente {self.addr} conectado como {self.username} desconectou com sucesso!\n')
                        self.active = False
                        self.callback.connections.remove(self)

                    elif cp_1.msgType == 'ok  ':
                        ...
                    elif cp_1.msgType == 'err ':
                        ...
                else:
                    if cp_1.msgType == 'publ':
                        cp_1.other_key = cp_1.msgValue
                        cp_1.quick_send('publ', message=cp_1.public_key,connection=True)
                        self.conn.sendall(cp_1.encode_raw())
                        self.cripto = True

                    elif cp_1.msgType == 'aesk':
                        cp_1.AES_key = cp_1.msgValue.encode('utf-8')
                        cp_1.quick_send('ok')
                        self.conn.sendall(cp_1.encode_raw())

                    else:
                        cp_1.quick_send('err', message='007')
                        self.conn.sendall(cp_1.encode_raw())

