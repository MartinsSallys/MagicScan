#!/usr/bin/env python3
import os, hashlib, json, argparse, re, requests
from tqdm import tqdm

CHUNK = 1024 * 1024
HASH_DB = "badhashes.json"
VT_URL = "https://www.virustotal.com/api/v3/files/"

def load_bad_hashes():
    if os.path.exists(HASH_DB):
        with open(HASH_DB) as f:
            return set(json.load(f))

    print("[*] Baixando base pública de hashes...")
    url = "https://bazaar.abuse.ch/export/txt/md5/recent/"
    r = requests.get(url, timeout=30)
    r.raise_for_status()

    hashes = set()
    for line in r.text.splitlines():
        if len(line) == 32:
            hashes.add(line.upper())

    with open(HASH_DB, "w") as f:
        json.dump(list(hashes), f)

    return hashes

BAD_HASHES = load_bad_hashes()

def load_bad_hashes():
    if os.path.exists(HASH_DB):
        print("[*] Usando base local de hashes")
        with open(HASH_DB) as f:
            return set(json.load(f))
    print("[!] Base local não encontrada.")
    print("[*] Tentando baixar hashes públicos (Abuse.ch)...")

    url = "https://bazaar.abuse.ch/export/txt/md5_recent.txt"
    hashes = set()

    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()

        for line in r.text.splitlines():
            line = line.strip()
            if len(line) == 32:
                hashes.add(line.upper())

        with open(HASH_DB, "w") as f:
            json.dump(list(hashes), f)

        print(f"[*] {len(hashes)} hashes carregados")
        return hashes

    except Exception as e:
        print("[!] Falha ao baixar hashes:", e)
        print("[!] Continuando SEM blacklist (modo heurístico)")
        return set() 
    
def is_pe(file_path):
    try:
        with open(file_path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), "little")
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except:
        return False

def scan(target):
    results = []
    for root, _, files in os.walk(target):
        for name in tqdm(files, desc=f"Scanning {root}", leave=False):
            path = os.path.join(root, name)
            try:
                md5, sha256 = calc_hashes(path)

                if md5 in BAD_HASHES:
                    results.append((path, md5, "HASH_BLACKLIST"))
                    continue

                if is_pe(path):
                    results.append((path, md5, "SUSPICIOUS_PE"))

            except Exception as e:
                with open("scan_errors.log", "a") as log:
                    log.write(f"{path}: {e}\n")

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MagicScan - Offline Malware Scanner")
    parser.add_argument("target", help="Diretório montado (ex: /mnt/windows)")
    args = parser.parse_args()

    print("[*] MagicScan iniciado")
    hits = scan(args.target)

    os.makedirs("reports", exist_ok=True)
    report = f"reports/report.json"

    with open(report, "w") as f:
        json.dump(hits, f, indent=2)

    print("\n[*] Scan finalizado")
    print(f"[*] Suspeitos encontrados: {len(hits)}")
    print(f"[*] Relatório salvo em {report}")
