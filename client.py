import socket
import threading
import time
import random
import protocol as cp

HOST = 'localhost'
PORT = 12321


def handle_received_message(sock, c):
    while True:
        try:
            data = sock.recv(4096)
        except ConnectionAbortedError:
            exit()
        c.decode_input(data)
        print('\r', end='')
        if c.msgType == 'brod':
            print(f'Broadcast recebido: ({c.msgValue.split(" ")[0]}) {" ".join(c.msgValue.split(" ")[1:])}')
        elif c.msgType == 'priv':
            print(f'Mensagem privada recebida: {c.msgValue}')
        elif c.msgType == 'ok  ':
            print(f'Comando realizado com sucesso:\n {c.msgValue}')
        elif c.msgType == 'err ':
            print('Erro:\n' + error_dict[c.msgValue])
        elif c.msgType == 'clos':
            print('Servidor fechando, finalizando processo')
            sock.close()
            exit()
        print('Digite uma mensagem a ser enviada ao servidor:')
        # print('')
        # print(f'Received {data.decode("utf-8")}')


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    error_dict = {'001': '',
                  '002': '',
                  '003': '',
                  '004': '',
                  '005': '',
                  '006': '',
                  '007': '',
                  '008': '',
                  '009': '',
                  }
    s.connect((HOST, PORT))

    cp_1 = cp.ProtocolMessage()
    cp_1.AES_key = b'oitudobemcomovce'  # TODO aleatorio aqui ó
    while True:
        cp_1.quick_send('publ', message=cp_1.public_key,connection=True)
        s.sendall(cp_1.encode_raw())
        data = s.recv(4096)
        cp_1.decode_raw(data)
        if cp_1.msgType == 'publ':
            cp_1.other_key = cp_1.msgValue
            break
        else:
            print('Erro:mensagem recebido não é a chave publica do servidor, tentando novamente...')

    while True:
        cp_1.quick_send('aesk', message=cp_1.AES_key,connection=True)
        s.sendall(cp_1.encode_rsa())
        data = s.recv(4096)
        cp_1.decode_raw(data)
        if cp_1.msgType == 'ok  ':
            break
        else:
            print('Erro:erro na recepcao do lado do servidor, tentando novamente...')
    # TODO fazer o processo de fcriptografar as mensagens

    while True:
        username = input('Digite seu nome de usuário: ')
        cp_1.quick_send('user', username)
        s.sendall(cp_1.encode())

        data = s.recv(4096)
        cp_1.decode_input(data)

        if cp_1.msgType == 'ok  ':
            print('Usuario aceito,prossiga com a senha...')
            break
        elif cp_1.msgType == 'err ':
            print('Erro:\n' + error_dict[cp_1.msgValue])

    while True:
        username = input('Digite sua senha: ')
        cp_1.quick_send('pass', username)
        s.sendall(cp_1.encode())

        data = s.recv(4096)
        cp_1.decode_input(data)

        if cp_1.msgType == 'ok  ':
            print('Senha aceita,conectado com sucesso...')
            break
        elif cp_1.msgType == 'err ':
            print('Erro:\n' + error_dict[cp_1.msgValue])

    c = cp.ProtocolMessage()
    c.private_key = cp_1.private_key
    c.public_key = cp_1.public_key
    c.AES_key = cp_1.AES_key
    c.other_key = cp_1.other_key

    t = threading.Thread(target=handle_received_message, args=(s, c,))
    t.start()

    connection_closed = False
    while True:
        try:
            time.sleep(.1)
            comando = 'mesg'
            text = input('Digite uma mensagem a ser enviada ao servidor:')
            if text[0] == '-':
                comando = text[1:5].lower()
                text = text[6:]
                if comando == 'priv':
                    pass
                elif comando == 'mesg':
                    pass
                elif comando == 'retr' or comando == 'clos':
                    text = ''
                else:
                    print('Comando inválido.')
                    continue

            cp_1.quick_send(comando.lower(), text)
            s.sendall(cp_1.encode())
            if comando == 'clos':
                connection_closed = True
                raise KeyboardInterrupt
        except KeyboardInterrupt or ConnectionAbortedError:
            print('')
            print('Encerrando o cliente...')
            if not connection_closed:  # isso nao ta servindo de nada. ainda da pau
                cp_1.quick_send('clos', '')
                s.sendall(cp_1.encode())
            time.sleep(.1)
            s.close()
            break

print('Bye bye!')
