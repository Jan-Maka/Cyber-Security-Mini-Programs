import struct

#Sends data to socket with a flag to indicate which operation is to be handled
def send_with_flag(sock, flag, data):
    flag_bytes = flag.encode().ljust(10,b' ')
    length = struct.pack('>I', len(data))
    sock.sendall(flag_bytes + length + data)

#Sends over data that was encrypted using AES
def send_aes_encrypted_data_with_flag(sock,flag,nonce,tag,ciphertext):
    data = nonce+ tag+ ciphertext
    send_with_flag(sock,flag,data)

#Recieves data for socket and divides the flag from actual data
def recv_with_flag(sock):
    flag = sock.recv(10).decode().strip()       
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
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket connection lost")
        data += chunk
    return data