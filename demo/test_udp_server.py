import socket
import threading

def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 5005))
    print("READY")
    data, addr = sock.recvfrom(1024)
    print(f"RECEIVED: {data.decode('utf-8')} from {addr}")
    sock.close()

if __name__ == "__main__":
    udp_server()
