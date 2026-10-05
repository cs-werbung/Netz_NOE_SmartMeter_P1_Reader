#!/usr/bin/env python3
"""
One-shot capture of P1 telegrams from the smart meter (diagnostics).

Reads the serial port for a few seconds and prints:
  1. the raw byte stream (hex)
  2. every M-Bus frame found (length, CI byte, checksum)
  3. per telegram: the joined DLMS PDU, the decrypted APDU and the Gurux XML

The decryption KEY is read from .env and is NEVER printed.

Usage (stop the reader service first, the port can only be opened once):
    sudo systemctl stop <service>
    python3 p1_capture.py                 # uses .env in the current dir
    python3 p1_capture.py /path/to/.env   # or an explicit .env
    python3 p1_capture.py --seconds 20    # capture longer (default 15)
    sudo systemctl start <service>

Output is also written to p1_capture_<timestamp>.txt
"""

import argparse
import binascii as ba
import os
import sys
import time
from datetime import datetime

import serial

out_lines = []


def log(s=''):
    print(s)
    out_lines.append(s)


def load_env(path):
    try:
        from dotenv import load_dotenv
        load_dotenv(path)
    except ImportError:                     # fallback: minimal .env parser
        if os.path.exists(path):
            for line in open(path):
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"\''))


def find_frames(stream: bytes):
    """Return list of (offset, frame, checksum_ok) for all M-Bus long frames."""
    frames, i = [], 0
    while i < len(stream) - 4:
        if stream[i] == 0x68 and stream[i + 3] == 0x68 and stream[i + 1] == stream[i + 2]:
            L = stream[i + 1]
            end = i + L + 6
            if end <= len(stream) and stream[end - 1] == 0x16:
                f = stream[i:end]
                frames.append((i, f, (sum(f[4:4 + L]) & 0xFF) == f[4 + L]))
                i = end
                continue
        i += 1
    return frames


def decrypt_pdu(pdu: bytes, key: bytes):
    from Crypto.Cipher import AES
    if pdu[0] != 0xDB:
        raise ValueError(f'PDU does not start with DB (general-glo-ciphering): {pdu[:4].hex()}')
    st_len = pdu[1]
    systitle = pdu[2:2 + st_len]
    p = 2 + st_len
    if pdu[p] & 0x80:
        n = pdu[p] & 0x7F
        length = int.from_bytes(pdu[p + 1:p + 1 + n], 'big')
        p += 1 + n
    else:
        length = pdu[p]
        p += 1
    sc = pdu[p]
    fc = pdu[p + 1:p + 5]
    ct = pdu[p + 5:p + length]
    log(f'  system title : {systitle.hex()}  (ASCII: {systitle[:3].decode("ascii", "replace")})')
    log(f'  length field : {length}  (bytes after it: {len(pdu) - p})'
        f'{"  OK" if len(pdu) - p == length else "  MISMATCH"}')
    log(f'  security ctrl: {sc:#04x}   frame counter: {int.from_bytes(fc, "big")}')
    return AES.new(key, AES.MODE_GCM, nonce=systitle + fc).decrypt(ct)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('env', nargs='?', default='.env')
    ap.add_argument('--seconds', type=int, default=15)
    args = ap.parse_args()

    load_env(args.env)
    port = os.getenv('PORT')
    baud = int(os.getenv('BAUD', '2400'))
    key_hex = os.getenv('KEY')
    if not port:
        sys.exit(f'PORT not set (looked for {os.path.abspath(args.env)})')

    log(f'# P1 capture {datetime.now().isoformat(timespec="seconds")}')
    log(f'# port={port} baud={baud} seconds={args.seconds} key={"set" if key_hex else "NOT SET"}')

    try:
        conn = serial.Serial(port=port, baudrate=baud, parity=serial.PARITY_NONE,
                             bytesize=serial.EIGHTBITS, stopbits=serial.STOPBITS_ONE,
                             timeout=0.2, exclusive=True)
    except (serial.SerialException, OSError) as e:
        sys.exit(f'Cannot open {port}: {e}\nIs the reader service still running? Stop it first.')

    # --- 1. raw capture, with gaps between bursts marked -----------------
    stream = bytearray()
    bursts = []                              # (start offset, time)
    t_end = time.time() + args.seconds
    last_rx = 0
    while time.time() < t_end:
        chunk = conn.read(1024)
        if chunk:
            now = time.time()
            if now - last_rx > 0.5:
                bursts.append((len(stream), now))
            last_rx = now
            stream.extend(chunk)
    conn.close()

    log(f'\n## 1. Raw stream: {len(stream)} bytes in {len(bursts)} bursts')
    for n, (off, ts) in enumerate(bursts):
        end = bursts[n + 1][0] if n + 1 < len(bursts) else len(stream)
        log(f'[burst {n} @ {datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]}, '
            f'{end - off} bytes]')
        log(stream[off:end].hex().upper())
    if not stream:
        sys.exit('No data received. Check cable, port and baud rate.')

    # --- 2. frames ---------------------------------------------------------
    frames = find_frames(bytes(stream))
    log(f'\n## 2. M-Bus frames found: {len(frames)}')
    for off, f, ok in frames:
        log(f'  @{off:5d}  len={len(f):3d}  L={f[1]:3d}  C={f[4]:02X} A={f[5]:02X} '
            f'CI={f[6]:02X}  next2={f[7:9].hex().upper()}  checksum={"OK" if ok else "BAD"}')

    # --- 3. telegrams: join segments, decrypt, translate -------------------
    log('\n## 3. Telegrams')
    if not key_hex:
        log('KEY not set -> no decryption. Raw data above is still useful.')
        return
    key = ba.unhexlify(key_hex)
    try:
        from gurux_dlms import GXDLMSTranslator
        try:
            from gurux_dlms import TranslatorOutputType
        except ImportError:
            from gurux_dlms.enums import TranslatorOutputType
        translator = GXDLMSTranslator(TranslatorOutputType.SIMPLE_XML)
    except Exception as e:
        translator = None
        log(f'(Gurux not available: {e})')

    data, n_tel, next_seq = bytearray(), 0, 0
    for off, f, ok in frames:
        if not ok:
            data.clear()
            next_seq = 0
            continue
        ci = f[6]
        if ci & 0x0F == 0:
            data.clear()
            next_seq = 0
        if ci & 0x0F != next_seq:
            log(f'  (frame @{off} CI={ci:02X} skipped: segment {ci & 0x0F}, '
                f'expected {next_seq} - capture started mid-telegram?)')
            data.clear()
            next_seq = 0
            continue
        next_seq += 1
        data.extend(f[9:-2])
        if not ci & 0x10:
            continue
        n_tel += 1
        log(f'\n### Telegram {n_tel} (last frame @{off})')
        pdu = bytes(data)
        data.clear()
        next_seq = 0
        log(f'  joined PDU ({len(pdu)} B): {pdu.hex().upper()}')
        try:
            apdu = decrypt_pdu(pdu, key)
            log(f'  decrypted APDU ({len(apdu)} B): {apdu.hex().upper()}')
            if translator:
                log(translator.pduToXml(apdu))
        except Exception as e:
            log(f'  ERROR: {e}')
        if n_tel >= 2:
            break
    if n_tel == 0:
        log('No complete telegram assembled (CI last-segment bit 0x10 never seen?).')

    fn = f'p1_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    with open(fn, 'w') as fh:
        fh.write('\n'.join(out_lines) + '\n')
    print(f'\nSaved to {fn}')


if __name__ == '__main__':
    main()
