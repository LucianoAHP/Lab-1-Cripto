import sys
import argparse
import string
from scapy.all import rdpcap, ICMP

GREEN = "\033[92m"
RESET = "\033[0m"

COMMON_SP_WORDS = [
    "la", "de", "en", "y", "que", "el", "por", "con", "para", "se", "es",
    "criptografia", "seguridad", "redes", "mensaje", "prueba"
]


def caesar_decrypt(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        else:
            out.append(ch)
    return ''.join(out)


def score_spanish(text: str) -> float:
    """Heurística simple para elegir la mejor rotación: palabras comunes + proporción de vocales."""
    t = text.lower()
    score = 0.0
    for w in COMMON_SP_WORDS:
        if w in t:
            score += 3.0 if len(w) > 6 else 1.0

    # bonus por proporción de vocales (español ~45–55% sobre letras)
    letters = [c for c in t if c.isalpha()]
    if letters:
        v = sum(c in "aeiouáéíóú" for c in letters) / len(letters)
        score += max(0.0, 1.0 - abs(v - 0.48) * 3)  # pico cerca de 0.48
    return score


def extract_text_from_pcap(pcap_path: str, use_payload: bool) -> str:
    packets = rdpcap(pcap_path)
    parts = []
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo Request
            if pkt.haslayer("Raw"):
                data: bytes = pkt["Raw"].load
                if not data:
                    continue
                if use_payload:
                    # Usar todo el payload, manteniendo solo imprimibles
                    parts.append(data.decode(errors="ignore"))
                else:
                    # Caso “1 carácter por paquete”: PRIMER byte
                    parts.append(chr(data[0]))
    return ''.join(parts)


def main():
    ap = argparse.ArgumentParser(description="Leer ICMP de pcap y romper César")
    ap.add_argument("pcap", help="Archivo .pcap o .pcapng con los ICMP capturados")
    ap.add_argument("--payload", action="store_true",
                    help="Reconstruir usando TODO el payload de cada paquete (no solo el 1er byte)")
    args = ap.parse_args()

    ciphertext = extract_text_from_pcap(args.pcap, use_payload=args.payload)

    if not ciphertext:
        print("No se extrajo texto del pcap. ¿El filtro es correcto y hay ICMP con datos?")
        sys.exit(2)

    print("[+] Texto capturado desde paquetes ICMP:")
    print(ciphertext)
    print("\n[+] Probando todas las rotaciones César:\n")

    best_shift = 0
    best_score = float("-inf")
    candidates = []

    for s in range(26):
        dec = caesar_decrypt(ciphertext, s)
        sc = score_spanish(dec)
        candidates.append((s, dec, sc))
        if sc > best_score:
            best_score = sc
            best_shift = s

    for s, dec, sc in candidates:
        if s == best_shift:
            print(f"{s:2d}: {GREEN}{dec}{RESET}")
        else:
            print(f"{s:2d}: {dec}")


if __name__ == "__main__":
    main()
