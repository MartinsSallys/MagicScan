# MagicScan 🧙‍♂️
MagicScan é uma ferramenta de **scan offline de malware** para sistemas Windows,
executada a partir de um **Linux Live** para evitar rootkits e técnicas de evasão.

## 🚀 Motivação
Malwares avançados conseguem se esconder quando o sistema infectado está em execução.
O MagicScan roda **fora do Windows**, analisando arquivos NTFS em modo read-only.

## 🛠️ Funcionalidades
- Scan por **hash MD5** (base pública)
- Detecção heurística simples (regex / YARA-like)
- Relatório em JSON
- Execução 100% offline (opcional)

## 📦 Requisitos
- Linux Live (Ubuntu, Fedora, Kali, etc.)
- Python 3
- Permissões de root
- Partição Windows montada como read-only

## ▶️ Uso básico

```bash
sudo mount -o ro /dev/sda2 /mnt/windows
sudo python3 magicscan.py /mnt/windows
