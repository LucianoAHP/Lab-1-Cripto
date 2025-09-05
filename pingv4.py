import os, time, random, socket, argparse
from scapy.all import IP, ICMP, Raw, send


def pad_payload(char: bytes, pad_to: int = 56) -> bytes:
    """Rellenar payload para que mida lo mismo que ping real (56 bytes)."""
    filler_len = max(0, pad_to - 1)
    filler = bytes([random.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(filler_len)])
    return char + filler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dest", help="IP o dominio destino")
    parser.add_argument("message", help="Mensaje a enviar (un caracter por paquete)")
    args = parser.parse_args()

    dst_ip = socket.gethostbyname(args.dest)
    icmp_id = os.getpid() & 0xFFFF

    print(f"[+] Enviando mensaje '{args.message}' a {dst_ip}")
    seq = 0

    for ch in args.message.encode("utf-8", errors="replace"):
        payload = pad_payload(bytes([ch]), pad_to=56)
        pkt = IP(dst=dst_ip, ttl=64) / ICMP(type=8, code=0, id=icmp_id, seq=seq) / Raw(load=payload)
        send(pkt, verbose=0)
        print("Sent 1 packets.")
        seq += 1
        time.sleep(1)


if __name__ == "__main__":
    main()
