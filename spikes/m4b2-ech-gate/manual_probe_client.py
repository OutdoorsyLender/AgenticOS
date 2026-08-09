import socket, sys, time
sys.path.insert(0, ".")
import chgen

mode = sys.argv[1] if len(sys.argv) > 1 else "ech1"
port = int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port))
if mode == "ech1":
    s.sendall(chgen.make_client_hello(b"approved.example.test", ech=True,
              extra_extensions=[(0xCAFE, b"\x01\x02")]))
elif mode == "cafe":
    s.sendall(chgen.make_client_hello(b"approved.example.test",
              extra_extensions=[(0xCAFE, b"\x01\x02")]))
elif mode == "noech":
    s.sendall(chgen.make_client_hello(b"approved.example.test"))
elif mode == "hrr":
    ch1 = chgen.make_client_hello(b"approved.example.test",
                                  supported_groups=[0x001D, 0x0018],
                                  key_share_group=0x0018)
    s.sendall(ch1)
    time.sleep(0.6)
    try:
        print("flight1:", s.recv(65536)[:16].hex())
    except OSError:
        pass
    ch2 = chgen.make_client_hello(b"approved.example.test", ech=True)
    s.sendall(ch2)
time.sleep(0.8)
try:
    print("flight:", s.recv(65536)[:24].hex())
except OSError as e:
    print("read err", e)
s.close()
