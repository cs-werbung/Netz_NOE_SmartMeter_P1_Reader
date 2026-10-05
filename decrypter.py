#!/usr/bin/env python3
'''
V0.1, 2021-12-14

Decryption and processing of smart meter telegrams:
* Smart meter: Sagemcom three-phase meter T210-D
* Grid operator: Netz NÖ

To use this script, the decryption key must be requested
from smartmeter@netz-noe.at.
'''

'''
V0.2, 2023-10-23

Renamed crypto library
Added voltage and current values for L1, L2 and L3
Added and adjusted QoS and retain flag
Added optional console output for debugging
'''

'''
V0.3, 2026-10-05

Frame synchronisation: bytes are buffered, only complete M-Bus frames
(68 L L 68 ... CS 16) with a valid checksum are processed
Telegram segments (2 M-Bus frames, CI 0x00 / 0x11) are joined before
decryption; system title, frame counter and length taken from the DLMS header
Values parsed by OBIS code from the Gurux XML (not by array position);
scaler and unit taken from the telegram, unit is checked per value
Decrypted APDU must start with 0x0F (DLMS DataNotification)
Plausibility checks: value ranges, kWh counters monotonic, max. increase/h
Startup: first value is only published once 2 frames agree
Retain=True (can be disabled via MQTT_RETAIN=false in .env): broker always
holds the last valid value, stale retained messages are overwritten
Payload as clean JSON (rounded, json.dumps), QoS 1
Automatic reconnect on serial interface errors
Optional TLS for MQTT (MQTT_TLS, MQTT_TLS_CA, MQTT_TLS_CERT, MQTT_TLS_KEY,
MQTT_TLS_INSECURE in .env); MQTT_PORT defaults to 8883 with TLS, 1883 without
'''

import binascii as ba
import json
import logging
import os
import time
import xml.etree.ElementTree as ET

import paho.mqtt.publish as mp
import serial
from Crypto.Cipher import AES
from dotenv import load_dotenv
from gurux_dlms import GXDLMSTranslator
try:                                        # location differs between Gurux versions
    from gurux_dlms import TranslatorOutputType
except ImportError:
    from gurux_dlms.enums import TranslatorOutputType

load_dotenv()

PORT = os.getenv('PORT')
BAUD = int(os.getenv('BAUD', '2400'))     # Netz NÖ spec: fixed 2400 baud
KEY = ba.unhexlify(os.getenv('KEY'))
LOGLEVEL = os.getenv('LOGLEVEL', 'WARNING')

MQTT_USER = os.getenv('MQTT_USER')
MQTT_PASS = os.getenv('MQTT_PASS')
MQTT_HOST = os.getenv('MQTT_HOST')
MQTT_TOPIC = os.getenv('MQTT_TOPIC')
MQTT_RETAIN = os.getenv('MQTT_RETAIN', 'true').lower() == 'true'

# Optional TLS for the MQTT connection (all settings in .env)
#   MQTT_TLS=true            enable TLS (default false)
#   MQTT_TLS_CA=/path/ca.crt CA certificate of the broker; empty = system CA store
#   MQTT_TLS_CERT=...        client certificate (only for client cert auth)
#   MQTT_TLS_KEY=...         client private key (only for client cert auth)
#   MQTT_TLS_INSECURE=true   skip host name check (e.g. broker addressed by IP
#                            but certificate issued for a name); still encrypted
MQTT_TLS = os.getenv('MQTT_TLS', 'false').lower() == 'true'
MQTT_TLS_CA = os.getenv('MQTT_TLS_CA') or None
MQTT_TLS_CERT = os.getenv('MQTT_TLS_CERT') or None
MQTT_TLS_KEY = os.getenv('MQTT_TLS_KEY') or None
MQTT_TLS_INSECURE = os.getenv('MQTT_TLS_INSECURE', 'false').lower() == 'true'
MQTT_PORT = int(os.getenv('MQTT_PORT') or (8883 if MQTT_TLS else 1883))

# Plausibility limits (adjust to your connection)
MAX_POWER_W = 60000          # > 3x63A x 230V
V_MIN, V_MAX = 150.0, 280.0
I_MAX = 100.0
MAX_KWH_PER_H = 70.0         # max energy increase rate (kWh per hour)
STARTUP_AGREE_KWH = 0.5      # two first frames must agree within this

logging.basicConfig(filename='/var/log/decrypter.log', encoding='utf-8',
                    level=LOGLEVEL, format='%(asctime)s %(levelname)s %(message)s')
t = GXDLMSTranslator(TranslatorOutputType.SIMPLE_XML)


def open_serial():
    while True:
        try:
            return serial.Serial(port=PORT, baudrate=BAUD, parity=serial.PARITY_NONE,
                                 bytesize=serial.EIGHTBITS, stopbits=serial.STOPBITS_ONE,
                                 timeout=1)
        except (serial.SerialException, OSError) as err:
            logging.error(f'Serial connection error: {err}; retry in 5 s')
            time.sleep(5)


def extract_frames(buf: bytearray):
    """Yield complete, checksum-valid M-Bus long frames; consume buf in place."""
    """Find a start: 
        look for the first 0x68 and drop everything before it (junk). 
        If there is none, empty the buffer.
    """
    """Check the header: 
        byte 1 must equal byte 2 (L twice), 
        byte 3 must be 0x68, and L must be at least 6  
        If not, it was a false start: drop one byte and search again.
    """
    """
        After this, there follow the function field (C field), the address field (A field) and the control information field (CI field)
        Followed by the Application Data
    """
    """
        Is it complete? If the buffer holds fewer than L+6 bytes, return and wait for the next read. The partial frame stays in the buffer.
        Validate: 
            the stop byte must be 0x16 and the checksum must match. 
            If not, the data is corrupted (cut off or a transmission error): drop one byte and resync.
    """
    while True:
        start = buf.find(b'\x68')
        # if no start byte
        if start < 0:
            buf.clear()
            return
        # if start not at 0 drop incomplete message parts before the start
        elif start > 0:
            del buf[:start]

        # gather more frames if the buffer doesn't contain a full M-Bus LONG Message header yet
        if len(buf) < 4:
            return

        # extract message length information
        length = buf[1]

        # Check for the complete header
        if buf[2] != length or buf[3] != 0x68 or length < 6:
            del buf[0]                      # false start byte
            continue

        # Check if the full length messages is received already
        total = length + 6
        if len(buf) < total:
            return                          # wait for more bytes

        # One complete message (total length)
        frame = bytes(buf[:total])

        # Checksum validation
        cs_ok = (sum(frame[4:4 + length]) & 0xFF) == frame[4 + length]
        if frame[-1] != 0x16 or not cs_ok:
            logging.info('Frame checksum/stop byte invalid, resync')
            del buf[0]
            continue

        # Clear Message from Buffer
        del buf[:total]

        # Return the frame: remove the frame from the buffer and hand it out with yield. Because it's a generator, main() can get several frames from one read.
        yield frame


class Assembler:
    """Joins the M-Bus segments of one telegram into one DLMS PDU.

    A Netz NÖ telegram is split into 2 M-Bus frames (256 + 26 bytes,
    verified on Sagemcom T210-D and in the Netz NÖ Kaifa sample):
      68 L L 68 | C A CI | 01 67 | user data ... | CS 16
    CI byte: low nibble = segment number, bit 0x10 = last segment
    (frame 1: CI=0x00, frame 2: CI=0x11). User data starts at byte 9.
    """
    def __init__(self):
        self.data = bytearray()
        self.next_seq = 0

    def add(self, frame: bytes):
        ci = frame[6]
        seq, last = ci & 0x0F, bool(ci & 0x10)
        if seq == 0:
            self.data.clear()               # first segment starts a new telegram
            self.next_seq = 0
        if seq != self.next_seq:
            logging.info(f'Unexpected segment {seq} (expected {self.next_seq}), dropped')
            self.data.clear()
            self.next_seq = 0
            return None
        self.data.extend(frame[9:-2])
        self.next_seq += 1
        if last:
            pdu = bytes(self.data)
            self.data.clear()
            self.next_seq = 0
            return pdu
        return None


def decrypt_pdu(pdu: bytes) -> bytes:
    """general-glo-ciphering PDU: DB | len | systitle | BER len | SC | FC | ciphertext"""
    if pdu[0] != 0xDB:
        raise ValueError(f'Not a general-glo-ciphering PDU: {pdu[:4].hex()}')
    st_len = pdu[1]
    systitle = pdu[2:2 + st_len]
    p = 2 + st_len
    if pdu[p] & 0x80:                       # BER long form, e.g. 81 F8
        n = pdu[p] & 0x7F
        length = int.from_bytes(pdu[p + 1:p + 1 + n], 'big')
        p += 1 + n
    else:
        length = pdu[p]
        p += 1
    if len(pdu) - p != length:
        raise ValueError(f'Length mismatch: header {length}, got {len(pdu) - p}')
    frame_counter = pdu[p + 1:p + 5]        # pdu[p] = security control byte
    ciphertext = pdu[p + 5:p + length]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=systitle + frame_counter)
    return cipher.decrypt(ciphertext)


def decode(pdu: bytes):
    apdu = decrypt_pdu(pdu)
    if not apdu or apdu[0] != 0x0F:
        raise ValueError(f'APDU does not start with 0x0F: {ba.hexlify(apdu[:8])}')

    return parse_values(ET.fromstring(t.pduToXml(apdu)))


# OBIS code -> (JSON key, unit expected from the meter, factor to output unit, decimals)
# Field names, types, scalers and units per Netz NÖ "Smart Meter Kundenschnittstelle P1"
# Units (DLMS enum): 0x1E Wh, 0x1B W, 0x23 V, 0x21 A, 0xFF none
OBIS_MAP = {
    '1-0:1.8.0':  ('kWh_in',  0x1E, 0.001, 3),   # A+  active energy import, Wh -> kWh
    '1-0:2.8.0':  ('kWh_out', 0x1E, 0.001, 3),   # A-  active energy export, Wh -> kWh
    '1-0:1.7.0':  ('pwr_in',  0x1B, 1, 0),       # P+  instantaneous power import, W
    '1-0:2.7.0':  ('pwr_out', 0x1B, 1, 0),       # P-  instantaneous power export, W
    '1-0:32.7.0': ('v_l1',    0x23, 1, 1),       # voltage L1, V
    '1-0:52.7.0': ('v_l2',    0x23, 1, 1),       # voltage L2, V
    '1-0:72.7.0': ('v_l3',    0x23, 1, 1),       # voltage L3, V
    '1-0:31.7.0': ('c_l1',    0x21, 1, 2),       # current L1, A
    '1-0:51.7.0': ('c_l2',    0x21, 1, 2),       # current L2, A
    '1-0:71.7.0': ('c_l3',    0x21, 1, 2),       # current L3, A
    '1-0:13.7.0': ('pf',      0xFF, 1, 3),       # power factor (optional)
}
REQUIRED_KEYS = {k for k, *_ in OBIS_MAP.values()} - {'pf'}


def hex_int(elem):
    """Integer from a Gurux XML element, signed if the type is Int8/16/32/64."""
    h = elem.attrib['Value']
    v = int(h, 16)
    if elem.tag.startswith('Int') and v >= 1 << (len(h) * 4 - 1):
        v -= 1 << (len(h) * 4)
    return v


def parse_values(root):
    """Parse the DataNotification by OBIS code instead of array position.

    The body is a flat structure of triplets:
      <OctetString Value="0100010800FF"/>   OBIS code (6 bytes)
      <UInt32 Value="00003289"/>            raw value
      <Structure><Int8 .. scaler/><Enum .. unit/></Structure>
    Other elements (timestamp, meter number) are skipped.
    """
    body = root.find('NotificationBody/DataValue/Structure')
    if body is None:
        raise ValueError('No NotificationBody/DataValue/Structure in XML')
    items = list(body)
    out = {}
    i = 0
    while i < len(items):
        e = items[i]
        h = e.attrib.get('Value', '')
        is_obis = (e.tag == 'OctetString' and len(h) == 12 and i + 2 < len(items)
                   and items[i + 2].tag == 'Structure' and len(items[i + 2]) == 2)
        if not is_obis:
            i += 1
            continue
        b = bytes.fromhex(h)
        obis = f'{b[0]}-{b[1]}:{b[2]}.{b[3]}.{b[4]}'
        raw = hex_int(items[i + 1])
        scaler_el, unit_el = items[i + 2]
        scaler = hex_int(scaler_el) if scaler_el.tag.startswith('Int') else \
            int.from_bytes(bytes.fromhex(scaler_el.attrib['Value']), 'big', signed=True)
        unit = int(unit_el.attrib['Value'], 16)
        i += 3
        if obis not in OBIS_MAP:
            logging.debug(f'Unknown OBIS {obis} = {raw} * 10^{scaler} (unit {unit:#x})')
            continue
        key, exp_unit, factor, dec = OBIS_MAP[obis]
        if unit != exp_unit:
            raise ValueError(f'{obis}: unit {unit:#x}, expected {exp_unit:#x}')
        value = round(raw * 10 ** scaler * factor, dec)
        out[key] = int(value) if dec == 0 else value
    missing = REQUIRED_KEYS - out.keys()
    if missing:
        raise ValueError(f'Missing values: {sorted(missing)}')
    return out


def in_range(v):
    return (0 <= v['pwr_in'] <= MAX_POWER_W and 0 <= v['pwr_out'] <= MAX_POWER_W
            and all(v[k] == 0 or V_MIN <= v[k] <= V_MAX       # 0 = phase down
                    for k in ('v_l1', 'v_l2', 'v_l3'))
            and all(0 <= v[k] <= I_MAX for k in ('c_l1', 'c_l2', 'c_l3'))
            and v['kWh_in'] > 0 and v['kWh_out'] >= 0)


class Validator:
    def __init__(self):
        self.last = None        # last accepted values
        self.last_ts = None
        self.candidate = None   # startup candidate

    def check(self, v):
        now = time.monotonic()
        if not in_range(v):
            return False, 'out of range'
        if self.last is None:
            # startup: need two consecutive agreeing frames
            if (self.candidate and
                    0 <= v['kWh_in'] - self.candidate['kWh_in'] <= STARTUP_AGREE_KWH and
                    0 <= v['kWh_out'] - self.candidate['kWh_out'] <= STARTUP_AGREE_KWH):
                self.last, self.last_ts = v, now
                return True, 'startup confirmed'
            self.candidate = v
            return False, 'startup candidate'
        dt_h = max((now - self.last_ts) / 3600.0, 1 / 360)  # >= 10 s
        for k in ('kWh_in', 'kWh_out'):
            d = v[k] - self.last[k]
            if d < 0:
                return False, f'{k} decreased {self.last[k]} -> {v[k]}'
            if d > MAX_KWH_PER_H * dt_h:
                return False, f'{k} jump {self.last[k]} -> {v[k]}'
        self.last, self.last_ts = v, now
        return True, 'ok'


def mqtt_tls_config():
    """TLS parameters for paho.mqtt.publish, or None if TLS is disabled.

    Returns a new dict on every call: paho removes the 'insecure' key
    from the dict it gets, so the same dict must not be reused.
    """
    if not MQTT_TLS:
        return None
    tls = {'ca_certs': MQTT_TLS_CA}
    if MQTT_TLS_CERT:
        tls['certfile'] = MQTT_TLS_CERT
        tls['keyfile'] = MQTT_TLS_KEY
    if MQTT_TLS_INSECURE:
        tls['insecure'] = True
    return tls


def check_tls_files():
    """Fail early with a clear message instead of an error on every publish."""
    if not MQTT_TLS:
        return
    for name, path in (('MQTT_TLS_CA', MQTT_TLS_CA), ('MQTT_TLS_CERT', MQTT_TLS_CERT),
                       ('MQTT_TLS_KEY', MQTT_TLS_KEY)):
        if path and not os.path.isfile(path):
            raise SystemExit(f'{name}: file not found: {path}')
    if bool(MQTT_TLS_CERT) != bool(MQTT_TLS_KEY):
        raise SystemExit('MQTT_TLS_CERT and MQTT_TLS_KEY must be set together')
    logging.info(f'MQTT TLS enabled, port {MQTT_PORT}, '
                 f'CA={MQTT_TLS_CA or "system"}, client cert={bool(MQTT_TLS_CERT)}, '
                 f'insecure={MQTT_TLS_INSECURE}')


def main():
    check_tls_files()
    conn = open_serial()
    buf = bytearray()
    validator = Validator()
    assembler = Assembler()
    auth = {'username': MQTT_USER, 'password': MQTT_PASS} if MQTT_USER else None

    while True:
        try:
            chunk = conn.read(512)
        except (serial.SerialException, OSError) as err:
            logging.error(f'Serial read error: {err}; reopening')
            time.sleep(2)
            conn = open_serial()
            buf.clear()
            assembler = Assembler()
            continue
        if not chunk:
            continue
        buf.extend(chunk)
        if len(buf) > 4096:                 # never grow unbounded
            del buf[:-1024]

        for frame in extract_frames(buf):
            pdu = assembler.add(frame)
            if pdu is None:
                continue                    # telegram not complete yet
            try:
                meterRead = decode(pdu)
            except Exception as e:
                logging.warning(f'Decode failed: {e}')
                continue

            ok, reason = validator.check(meterRead)
            if not ok:
                logging.warning(f'Rejected ({reason}): {meterRead}')
                continue

            try:
                mp.single(MQTT_TOPIC, json.dumps(meterRead), qos=1, retain=MQTT_RETAIN,
                          hostname=MQTT_HOST, port=MQTT_PORT, auth=auth,
                          tls=mqtt_tls_config())
            except Exception as e:
                logging.error(f'MQTT publish failed: {e}')


if __name__ == '__main__':
    main()