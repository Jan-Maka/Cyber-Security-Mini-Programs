import struct

#Sends data to socket with a flag to indicate which operation is to be handled
def send_with_flag(sock, flag, data):
    flag_bytes = flag.encode()
    flag_len = len(flag_bytes)
    length = struct.pack('>I', len(data))            # 4 bytes: data length
    sock.sendall(struct.pack('B', flag_len) +        # 1 byte: flag length
                 flag_bytes +                        # N bytes: flag
                 length +                            # 4 bytes: data length
                 data)        

#Sends over data that was encrypted using AES
def send_aes_encrypted_data_with_flag(sock,flag,nonce,tag,ciphertext):
    data = nonce+ tag+ ciphertext
    send_with_flag(sock,flag,data)

#Recieves data for socket and divides the flag from actual data
def recv_with_flag(sock):
    flag_len_bytes = recv_exact(sock, 1)
    if not flag_len_bytes:
        return None, None
    flag_len = flag_len_bytes[0]

    flag = recv_exact(sock, flag_len).decode()

    raw_length = recv_exact(sock, 4)
    if not raw_length:
        return None, None
    data_length = struct.unpack('>I', raw_length)[0]

    data = recv_exact(sock, data_length)
    return flag, data

#Gets the exact amount of the data received by the socket
def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed prematurely")
        data += packet
    return data