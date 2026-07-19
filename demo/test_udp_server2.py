import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5005))
print("Bound to 0.0.0.0:5005")
data, addr = s.recvfrom(1024)
print(f"Received from {addr}: {data}")
