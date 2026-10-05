# Netz NÖ SmartMeter P1 Reader

Reads the P1 customer interface of a smart meter operated by Netz NÖ (tested with the
**Sagemcom T210-D**), decrypts the DLMS telegrams and publishes the values as JSON to an
MQTT broker (e.g. Home Assistant + Mosquitto).

Specification of the interface (Netz NÖ):
https://www.netz-noe.at/Download-(1)/Smart-Meter/218_9_SmartMeter_Kundenschnittstelle_lektoriert_14.aspx
https://community.symcon.de/uploads/short-url/scJg8Irz6VRWPUcftQYr5LhPWwV.pdf

## Published values

Topic: `MQTT_TOPIC` (e.g. `/home/smartmeter/vals`), one message every 5 seconds:

```json
{"kWh_in": 47801.696, "kWh_out": 35.41, "pwr_in": 20, "pwr_out": 0,
  "v_l1": 235.6, "v_l2": 235.1, "v_l3": 236.1,
  "c_l1": 2.83, "c_l2": 3.25, "c_l3": 3.25, "pf": 0.009}
```

| Key | OBIS | Meaning | Unit |
|---|---|---|---|
| `kWh_in` | 1-0:1.8.0 | Active energy import A+ (total) | kWh |
| `kWh_out` | 1-0:2.8.0 | Active energy export A− (total) | kWh |
| `pwr_in` | 1-0:1.7.0 | Instantaneous power import P+ | W |
| `pwr_out` | 1-0:2.7.0 | Instantaneous power export P− | W |
| `v_l1` … `v_l3` | 1-0:32/52/72.7.0 | Voltage L1–L3 | V |
| `c_l1` … `c_l3` | 1-0:31/51/71.7.0 | Current L1–L3 | A |
| `pf` | 1-0:13.7.0 | Power factor (optional) | – |

Notes:
- The meter nets all three phases. With PV/battery, `pwr_in`/`pwr_out` are the net values;
  only one of them is > 0 at a time.
- Currents are magnitudes without direction. With PV/battery a low `pf` is normal.

## How it works

1. **Frame sync:** the serial byte stream is buffered; only complete M-Bus frames
   (`68 L L 68 … CS 16`) with a valid checksum are used.
2. **Segment assembly:** each telegram arrives as 2 M-Bus frames (256 + 26 bytes,
   CI byte `0x00` / `0x11`). The user data of both frames is joined.
3. **Decryption:** AES-128-GCM (DLMS security suite 0). System title, frame counter and
   length are read from the DLMS header (`DB 08 … 81 F8 20 …`); the length is checked.
4. **Parsing:** the decrypted APDU must be a DLMS DataNotification (`0x0F`). Gurux converts it
   to XML; values are looked up **by OBIS code**, scaler and unit are taken from the
   telegram and the unit is verified.
5. **Plausibility checks:** value ranges, energy counters must never decrease,
   max. 70 kWh/h increase. After start, the first value is only published once two
   consecutive telegrams agree.
6. **MQTT:** JSON, QoS 1, `retain=true` (configurable), optional TLS.

Invalid telegrams are discarded and logged; nothing implausible is published. This prevents
spikes in the Home Assistant energy statistics (e.g. after a reboot).

## Installation

Requires Python 3.9 or newer (Raspberry Pi OS Bullseye, Bookworm, Trixie).

```bash
sudo apt update
sudo apt install -y git python3-venv
git clone https://github.com/cs-werbung/Netz_NOE_SmartMeter_P1_Reader.git
cd Netz_NOE_SmartMeter_P1_Reader
python3 -m venv venv                       # virtual environment in ./venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
cp .env.example .env
nano .env                                  # enter KEY, MQTT settings
venv/bin/python decrypter.py               # test run, stop with Ctrl+C
```

Why a virtual environment: since Debian 12 (Raspberry Pi OS Bookworm), `pip install`
into the system Python fails with `error: externally-managed-environment`. The venv
keeps the libraries separate from the system; always start the scripts with
`venv/bin/python` (no `activate` needed). Do **not** use `--break-system-packages`.

Updating the libraries later:
```bash
venv/bin/pip install --upgrade -r requirements.txt
```

- The **KEY** (decryption key, 32 hex digits) must be requested from Netz NÖ
  (smartmeter@netz-noe.at or the Smart Meter web portal).
- If the script does not run as root, create the log file and grant access:
  ```bash
  sudo touch /var/log/decrypter.log && sudo chown pi:pi /var/log/decrypter.log
  ```
- The user needs access to the serial port: `sudo usermod -aG dialout pi` (log out and in again)

### Configuration (.env)

See [`.env.example`](.env.example) for all options.

| Variable | Default | Description |
|---|---|---|
| `PORT` | – | Serial device, e.g. `/dev/ttyUSB0` |
| `BAUD` | `2400` | Baud rate (Netz NÖ: 2400) |
| `KEY` | – | Decryption key from Netz NÖ (32 hex digits) |
| `LOGLEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `MQTT_HOST` | – | Broker address |
| `MQTT_PORT` | `1883` / `8883` with TLS | Broker port |
| `MQTT_USER`, `MQTT_PASS` | – | Broker login (empty = anonymous) |
| `MQTT_TOPIC` | – | Topic, e.g. `/home/smartmeter/vals` |
| `MQTT_RETAIN` | `true` | Broker keeps the last valid value |
| `MQTT_TLS` | `false` | Enable TLS |
| `MQTT_TLS_CA` | system CAs | CA certificate of the broker |
| `MQTT_TLS_CERT`, `MQTT_TLS_KEY` | – | Client certificate and key (optional) |
| `MQTT_TLS_INSECURE` | `false` | Skip host name check (still encrypted) |

Plausibility limits (`MAX_POWER_W`, `V_MIN`/`V_MAX`, `I_MAX`, `MAX_KWH_PER_H`) can be adjusted
at the top of `decrypter.py`.

## Run as a service

Create `/etc/systemd/system/smartmeterd.service` (adjust `User`, `Group`, paths):

```ini
[Unit]
Description=Smart Meter Decrypter
Documentation=https://github.com/cs-werbung/Netz_NOE_SmartMeter_P1_Reader
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
Group=pi
WorkingDirectory=/home/pi/Netz_NOE_SmartMeter_P1_Reader
ExecStart=/home/pi/Netz_NOE_SmartMeter_P1_Reader/venv/bin/python /home/pi/Netz_NOE_SmartMeter_P1_Reader/decrypter.py
Restart=always
RestartSec=30s

[Install]
WantedBy=multi-user.target
```

`WorkingDirectory` must be the folder containing `.env`; `ExecStart` must use the Python
of the venv (`venv/bin/python`), otherwise the libraries are not found.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now smartmeterd
sudo systemctl status smartmeterd
sudo journalctl -u smartmeterd -e     # if there are problems
tail -f /var/log/decrypter.log
```

## Diagnostics: capture a telegram

`p1_capture.py` reads the port for 15 s and prints the raw data, all M-Bus frames and the
decrypted telegrams (the key is never printed). Stop the service first:

```bash
sudo systemctl stop smartmeterd
venv/bin/python p1_capture.py      # optional: --seconds 30
sudo systemctl start smartmeterd
```

Output is also saved to `p1_capture_<timestamp>.txt`. It contains the meter number
and system title; remove them before sharing.

## Home Assistant

Recommended: Home Assistant + Mosquitto broker add-on.

```yaml
mqtt:
  sensor:
    - name: SmartMeter kWh in
      unique_id: smartmeter_kwh_in
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.kWh_in }}"
      unit_of_measurement: "kWh"
      device_class: energy
      state_class: total_increasing
    - name: SmartMeter kWh out
      unique_id: smartmeter_kwh_out
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.kWh_out }}"
      unit_of_measurement: "kWh"
      device_class: energy
      state_class: total_increasing
    - name: SmartMeter Power in
      unique_id: smartmeter_power_in
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.pwr_in }}"
      unit_of_measurement: "W"
      device_class: power
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Power out
      unique_id: smartmeter_power_out
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.pwr_out }}"
      unit_of_measurement: "W"
      device_class: power
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Voltage L1
      unique_id: smartmeter_voltage_l1
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.v_l1 }}"
      unit_of_measurement: "V"
      device_class: voltage
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Voltage L2
      unique_id: smartmeter_voltage_l2
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.v_l2 }}"
      unit_of_measurement: "V"
      device_class: voltage
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Voltage L3
      unique_id: smartmeter_voltage_l3
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.v_l3 }}"
      unit_of_measurement: "V"
      device_class: voltage
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Current L1
      unique_id: smartmeter_current_l1
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.c_l1 }}"
      unit_of_measurement: "A"
      device_class: current
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Current L2
      unique_id: smartmeter_current_l2
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.c_l2 }}"
      unit_of_measurement: "A"
      device_class: current
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Current L3
      unique_id: smartmeter_current_l3
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.c_l3 }}"
      unit_of_measurement: "A"
      device_class: current
      state_class: measurement
      expire_after: 60
    - name: SmartMeter Power Factor
      unique_id: smartmeter_power_factor
      state_topic: "/home/smartmeter/vals"
      value_template: "{{ value_json.pf | default(none) }}"
      device_class: power_factor
      state_class: measurement
      expire_after: 60
```

- **Energy dashboard:** grid consumption = `SmartMeter kWh in`, return to grid = `SmartMeter kWh out`.
- `expire_after: 60` marks live values as unavailable if no message arrives for 60 s.
  It is deliberately not set on the energy counters, so they keep their last value.
- **Upgrading from an older version:** an old *retained* message on the topic can make
  Home Assistant read an outdated meter value after a restart (shows up as a huge spike in
  the energy statistics). Clear it once:
  ```bash
  mosquitto_pub -h <broker> -u <user> -P <pass> -t /home/smartmeter/vals -r -n
  ```
  Wrong statistic entries can be corrected in *Developer tools → Statistics → Adjust sum*.

## Hardware

- USB to M-Bus slave module (e.g. BELTI, Amazon)
- RJ12 cable (P1 customer interface, pins 3/4 = M-Bus)
- Raspberry Pi

## Version history

- **V0.1** (2021-12-14): decryption and processing of T210-D telegrams
- **V0.2** (2023-10-23): voltage/current L1–L3, QoS/retain, debug output
- **V0.3** (2026-10-05): frame sync with checksum, joining of the 2 M-Bus segments,
  DLMS header parsing, OBIS-based parsing with scaler/unit check, plausibility checks,
  retained last valid value, optional MQTT TLS, serial reconnect, `p1_capture.py`