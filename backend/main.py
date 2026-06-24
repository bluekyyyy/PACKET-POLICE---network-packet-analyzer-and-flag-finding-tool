from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
import pyshark
import tempfile
import re
import os
import asyncio 
import base64
import urllib.parse
import codecs
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/upload")
def analyze_pcap(file: UploadFile = File(...), display_filter: str = Form(""), api_key: str = Form("")): 
    asyncio.set_event_loop(asyncio.new_event_loop())
    
    # DYNAMIC EXTENSION FIX: Preserves .pcapng so TShark parses it correctly
    _, file_ext = os.path.splitext(file.filename)
    if not file_ext: file_ext = ".pcap"

    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
        temp_file.write(file.file.read()) 
        temp_path = temp_file.name

    packet_data = []
    filter_arg = display_filter if display_filter.strip() else None
    
    cap = pyshark.FileCapture(temp_path, display_filter=filter_arg, include_raw=True, use_json=True)
    
    for i, pkt in enumerate(cap):
        if i >= 100: break 
        
        # 1. Isolate Layer Parsing with AGGRESSIVE SANITATION
        parsed_layers = []
        try:
            for layer in pkt.layers:
                layer_data = {"name": layer.layer_name.upper(), "fields": []}
                for field in layer.field_names:
                    # STRICT BYPASS: Drop all Wireshark internal developer noise
                    if field.endswith('_raw') or field.endswith('_tree') or field.endswith('_resolved') or field == 'expert':
                        continue
                    try:
                        val = getattr(layer, field)
                        val_str = str(val)
                        
                        # Skip empty variables or weird unparsed JSON arrays
                        if not val_str or val_str == "None" or val_str.startswith("["):
                            continue
                            
                        # Strip out ANSI terminal color codes (the [1m[33m garbage)
                        clean_val = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', val_str)
                        clean_key = field.replace('_', ' ').title()
                        
                        layer_data["fields"].append({"key": clean_key, "val": clean_val})
                    except Exception:
                        pass
                
                if layer_data["fields"]:
                    parsed_layers.append(layer_data)
        except Exception:
            pass

        # 2. Hex Extraction
        raw_hex = ""
        try:
            raw_bytes = pkt.get_raw_packet()
            if raw_bytes:
                raw_hex = raw_bytes.hex()
        except Exception:
            pass

        # 3. Timestamp Parsing
        time_str = "N/A"
        try:
            time_str = pkt.sniff_time.strftime("%H:%M:%S")
        except Exception:
            try:
                dt = datetime.fromisoformat(str(pkt.sniff_timestamp).replace('Z', '+00:00'))
                time_str = dt.strftime("%H:%M:%S")
            except Exception:
                pass

        # 4. IP Parsing
        src_ip = "N/A"
        dst_ip = "N/A"
        try:
            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
            elif hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst
            elif hasattr(pkt, 'eth'):
                src_ip = pkt.eth.src
                dst_ip = pkt.eth.dst
        except Exception:
            pass

        # 5. Protocol 
        try:
            proto = pkt.highest_layer
        except Exception:
            proto = "Unknown"

        packet_data.append({
            "no": i + 1,
            "protocol": proto,
            "source": src_ip,
            "destination": dst_ip,
            "info": time_str,
            "details": parsed_layers,
            "raw_hex": raw_hex
        })
            
    cap.close()
    os.remove(temp_path)
    return {"packets": packet_data}

@app.post("/api/find_flags")
def find_flags(file: UploadFile = File(...), display_filter: str = Form(""), api_key: str = Form("")): 
    asyncio.set_event_loop(asyncio.new_event_loop())
    
    # Python 3.13 Safe Strict Regex
    flag_regex = r"[A-Za-z0-9_-]{3,25}\{[A-Za-z0-9_!@#$%^&*()\-+=.<>?]{4,60}\}"
    found_flags = set()
    
    # DYNAMIC EXTENSION FIX: Preserves .pcapng so TShark parses it correctly
    _, file_ext = os.path.splitext(file.filename)
    if not file_ext: file_ext = ".pcap"

    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
        temp_file.write(file.file.read()) 
        temp_path = temp_file.name

    filter_arg = display_filter if display_filter.strip() else None
    cap = pyshark.FileCapture(temp_path, display_filter=filter_arg, include_raw=True, use_json=True)
    
    stitched_data_b64 = ""
    raw_stream = ""

    for pkt in cap:
        try:
            raw_bytes = pkt.get_raw_packet()
            if raw_bytes:
                raw_str = raw_bytes.decode('utf-8', errors='ignore')
                raw_stream += raw_str

                matches = re.findall(r'data=([A-Za-z0-9+/=]+)', raw_str)
                for m in matches:
                    stitched_data_b64 += m
        except Exception:
            continue
            
    cap.close()
    os.remove(temp_path)

    def hunt_in_text(text, source_name):
        clean_text = text.replace('\n', '').replace('\r', '').replace(' ', '')
        
        for m in re.findall(flag_regex, text): found_flags.add(f"{m} (Cleartext - {source_name})")
            
        for b64 in re.findall(r'[A-Za-z0-9+/=]{12,}', clean_text):
            try:
                padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
                b64_dec = base64.b64decode(padded).decode('utf-8', errors='ignore')
                for m in re.findall(flag_regex, b64_dec): found_flags.add(f"{m} (Base64 - {source_name})")
            except: pass

        url_dec = urllib.parse.unquote(text)
        if url_dec != text:
            for m in re.findall(flag_regex, url_dec): found_flags.add(f"{m} (URL Decoded - {source_name})")
                
        rot13_dec = codecs.decode(text, 'rot_13')
        for m in re.findall(flag_regex, rot13_dec): found_flags.add(f"{m} (ROT13 - {source_name})")

        atbash_trans = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")
        atbash_dec = text.translate(atbash_trans)
        for m in re.findall(flag_regex, atbash_dec): found_flags.add(f"{m} (Atbash - {source_name})")

        for hex_str in re.findall(r'[0-9A-Fa-f]{16,}', clean_text):
            try:
                hex_dec = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                for m in re.findall(flag_regex, hex_dec): found_flags.add(f"{m} (Hex - {source_name})")
            except: pass

        for b32 in re.findall(r'[A-Z2-7=]{16,}', clean_text.upper()):
            try:
                padded = b32 + "=" * ((8 - len(b32) % 8) % 8)
                b32_dec = base64.b32decode(padded).decode('utf-8', errors='ignore')
                for m in re.findall(flag_regex, b32_dec): found_flags.add(f"{m} (Base32 - {source_name})")
            except: pass

    hunt_in_text(raw_stream, "Raw Stream")
    if stitched_data_b64:
        hunt_in_text(stitched_data_b64, "Stitched 'data=' Chunks")
        try:
            padded = stitched_data_b64 + "=" * ((4 - len(stitched_data_b64) % 4) % 4)
            direct_dec = base64.b64decode(padded).decode('utf-8', errors='ignore')
            for m in re.findall(flag_regex, direct_dec): found_flags.add(f"{m} (Direct Base64 Stitch)")
        except: pass

    return {"flags": list(found_flags)}