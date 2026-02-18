import os
import json
import ipaddress
import time
import sys
import subprocess
import socket
import re
from datetime import datetime
import msvcrt

# ==========================================
#        تنظیمات و ثابت‌ها
# ==========================================
os.system('') 
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    GREY = '\033[90m'

try:
    import requests
    import socks
except ImportError:
    print(f"{Colors.FAIL}Error: requests or pysocks module missing.{Colors.ENDC}")
    sys.exit(1)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(CURRENT_DIR, "config.json")
TEMP_CONFIG_FILE = os.path.join(CURRENT_DIR, "config_temp.json")
RANGES_FILE = os.path.join(CURRENT_DIR, "ranges.txt")
XRAY_PATH = os.path.join(CURRENT_DIR, "xray.exe")
CLEAN_IPS_DIR = os.path.join(CURRENT_DIR, "clean_ips")
IPERF_DIR = os.path.join(CURRENT_DIR, "iperf")
IPERF_EXE = os.path.join(IPERF_DIR, "iperf3.exe")
if not os.path.exists(IPERF_EXE): IPERF_EXE = os.path.join(IPERF_DIR, "iperf.exe")

# پورت‌های اختصاصی
SOCKS_PORT = 14567
IPERF_PORT = 14568
TEST_URL = "http://www.gstatic.com/generate_204"

def print_banner():
    print(Colors.HEADER + "╔" + "═"*70 + "╗" + Colors.ENDC)
    print(Colors.HEADER + "║" + Colors.BOLD + "       💎 XRAY SCANNER        " + Colors.ENDC + Colors.HEADER + "║" + Colors.ENDC)
    print(Colors.HEADER + "╚" + "═"*70 + "╝" + Colors.ENDC)

# ==========================================
#        1. هسته منطقی (دست نخورده)
# ==========================================

def get_target_outbound(config):
    if "outbounds" in config:
        for out in config["outbounds"]:
            if out.get("protocol") in ["vmess", "vless", "trojan", "shadowsocks"]:
                return out
    return None

def create_scan_config(base_config, new_ip, iperf_host, iperf_port):
    """
    منطق اصلی: حفظ SNI و تنظیم Dokodemo
    """
    outbound_original = get_target_outbound(base_config)
    if not outbound_original:
        raise ValueError("No valid Proxy outbound found.")
    
    outbound = json.loads(json.dumps(outbound_original))
    outbound["tag"] = "PROXY_OUT"

    original_address = ""
    settings = outbound.get("settings", {})
    proto = outbound.get("protocol", "")
    
    if proto in ["vmess", "vless"]:
        if "vnext" in settings and settings["vnext"]:
            original_address = settings["vnext"][0]["address"]
            settings["vnext"][0]["address"] = new_ip
    elif proto in ["trojan", "shadowsocks"]:
        if "servers" in settings and settings["servers"]:
            original_address = settings["servers"][0]["address"]
            settings["servers"][0]["address"] = new_ip

    # اصلاح SNI (حیاتی)
    stream = outbound.get("streamSettings", {})
    security = stream.get("security", "none")
    
    if security in ["tls", "reality", "xtls"]:
        tls_settings = stream.get(f"{security}Settings", {})
        if "serverName" not in tls_settings or not tls_settings["serverName"]:
            tls_settings["serverName"] = original_address
        stream[f"{security}Settings"] = tls_settings
    
    if stream.get("network") in ["ws", "http", "tcp"]:
        net_settings = stream.get(f"{stream.get('network')}Settings", {})
        if "headers" not in net_settings: net_settings["headers"] = {}
        if "Host" not in net_settings["headers"] or not net_settings["headers"]["Host"]:
             net_settings["headers"]["Host"] = original_address
        stream[f"{stream.get('network')}Settings"] = net_settings

    outbound["streamSettings"] = stream

    final_structure = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"tag": "SOCKS_IN", "port": SOCKS_PORT, "protocol": "socks", "settings": {"udp": True}, "listen": "127.0.0.1"},
            {"tag": "IPERF_IN", "port": IPERF_PORT, "protocol": "dokodemo-door", "settings": {"address": iperf_host, "port": iperf_port, "network": "tcp,udp"}, "listen": "127.0.0.1"}
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "DIRECT"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["SOCKS_IN", "IPERF_IN"], "outboundTag": "PROXY_OUT"}]
        }
    }
    return final_structure

# ==========================================
#        2. ابزارهای اجرا
# ==========================================

def parse_cmd(u_cmd):
    parts = u_cmd.split()
    host, port, dur = "", 5201, 10
    try:
        if "-c" in parts: host = parts[parts.index("-c")+1]
        if "-p" in parts: port = int(parts[parts.index("-p")+1])
        if "-t" in parts: dur = int(parts[parts.index("-t")+1])
    except: pass
    
    if not host: return None, None, None, None
    
    new_cmd = [IPERF_EXE, "-c", "127.0.0.1", "-p", str(IPERF_PORT), "-4"]
    skip = False
    for p in parts:
        if skip: skip=False; continue
        if p in ["-c", "-p", "-4"]: skip=True; continue
        if "iperf" in p.lower(): continue
        new_cmd.append(p)
        
    return host, port, dur, new_cmd

def run_iperf_task(cmd, duration):
    try:
        # اصلاح: افزایش زمان انتظار (Buffer) از 5 به 20 ثانیه
        # این کار باعث می‌شود در تست‌های طولانی (60s)، تاخیر شبکه باعث بسته شدن برنامه نشود.
        safety_buffer = 20 
        
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                            text=True, encoding='utf-8', errors='replace', timeout=duration + safety_buffer)
        
        out = proc.stdout
        speed, loss = 0.0, 0.0
        
        # استخراج سرعت
        s = re.findall(r'(\d+\.?\d*)\s+([KMG]bits/sec)', out)
        if s:
            v, u = s[-1]
            v = float(v)
            if 'K' in u: v/=1000
            elif 'G' in u: v*=1000
            speed = v
            
        # استخراج پکت لاس
        l = re.findall(r'\((\d+\.?\d*)%\)', out)
        if l: loss = float(l[-1])
        
        # بررسی موفقیت آمیز بودن
        if speed == 0 and proc.returncode != 0:
            # اگر سرعت 0 بود، لاگ خطا را برای دیباگ کوتاه برگردان
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown"
            return 0, 100, f"Fail: {err_msg}"
            
        return speed, loss, "OK"

    except subprocess.TimeoutExpired:
        return 0, 100, "Timeout"
    except Exception as e:
        return 0, 100, "Err"


# ==========================================
#        3. ذخیره نتایج (اصلاح شده: ۳ فایل)
# ==========================================

def save_res_final(data):
    if not data: return
    if not os.path.exists(CLEAN_IPS_DIR): os.makedirs(CLEAN_IPS_DIR)
    
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    save_path = os.path.join(CLEAN_IPS_DIR, ts)
    os.makedirs(save_path)
    
    # 1. مرتب‌سازی بر اساس سرعت (زیاد به کم)
    with open(os.path.join(save_path, "sorted_by_speed.json"), 'w', encoding='utf-8') as f:
        json.dump(sorted(data, key=lambda x: x['speed_mbps'], reverse=True), f, indent=2)

    # 2. مرتب‌سازی بر اساس پکت لاس (کم به زیاد)
    with open(os.path.join(save_path, "sorted_by_loss.json"), 'w', encoding='utf-8') as f:
        json.dump(sorted(data, key=lambda x: x['packet_loss']), f, indent=2)

    # 3. مرتب‌سازی بر اساس Delay (کم به زیاد)
    with open(os.path.join(save_path, "sorted_by_delay.json"), 'w', encoding='utf-8') as f:
        json.dump(sorted(data, key=lambda x: x['real_delay']), f, indent=2)
        
    print(f"\n{Colors.GREEN}[Done] Results saved in 3 files at: {save_path}{Colors.ENDC}")

# ==========================================
#        Main Loop (اصلاح شده: UI)
# ==========================================
# متغیرهای کنترل وضعیت
IS_PAUSED = False
STOP_REQUESTED = False

def check_keyboard_input():
    """بررسی دکمه‌های P (پوز), S (ادامه), Ctrl+C (توقف)"""
    global IS_PAUSED, STOP_REQUESTED
    
    # اگر کلیدی فشرده شده باشد
    if msvcrt.kbhit():
        key = msvcrt.getch()
        
        # دکمه P یا p (Pause)
        if key.lower() == b'p':
            IS_PAUSED = True
            print(f"\n{Colors.WARNING}⏸  SCAN PAUSED. Press 's' to resume...{Colors.ENDC}")
            
        # دکمه S یا s (Start/Resume)
        elif key.lower() == b's':
            IS_PAUSED = False
            print(f"\n{Colors.GREEN}▶  RESUMING SCAN...{Colors.ENDC}")
            
        # دکمه Ctrl+C (کد اسکی 3)
        elif key == b'\x03':
            STOP_REQUESTED = True
            print(f"\n{Colors.FAIL}⏹  STOP REQUESTED! Saving current results...{Colors.ENDC}")
            return True # سیگنال خروج
            
    return False


def scan():
    print_banner()
    
    # --- ورودی ---
    def_cmd = "-c speedtest.uztelecom.uz -p 5201 -t 5 -4"
    u_cmd = input(f"{Colors.CYAN}Enter iPerf command (Default: Enter):{Colors.ENDC}\n>> ").strip() or def_cmd
    
    host, port, dur, iperf_cmd = parse_cmd(u_cmd)
    if not host: print("Error: Invalid iPerf command"); return
    
    print(f"\n{Colors.BLUE}Target: {host}:{port} | Duration: {dur}s | LocalTunnel: {IPERF_PORT}{Colors.ENDC}\n")

    # --- فایل‌ها ---
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f: base = json.load(f)
        with open(RANGES_FILE, 'r') as f: raw_ranges = [x.strip() for x in f if x.strip()]
    except Exception as e:
        print(f"File Error: {e}"); return
        
    # --- پیش‌محاسبه برای درصد کلی ---
    print(f"{Colors.GREY}[Init] Calculating total IPs...{Colors.ENDC}")
    valid_ranges = []
    total_global_ips = 0
    for r in raw_ranges:
        try:
            net = ipaddress.ip_network(r, strict=False)
            total_global_ips += net.num_addresses
            valid_ranges.append(net)
        except ValueError:
            print(f"{Colors.FAIL}Invalid Range Skipped: {r}{Colors.ENDC}")
            
    total_range_count = len(valid_ranges)
    print(f"{Colors.GREEN}[Ready] Total Ranges: {total_range_count} | Total IPs: {total_global_ips}{Colors.ENDC}\n")

    # تنظیمات ویندوز
    si = None
    if sys.platform == 'win32':
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    results = []
    global_ip_counter = 0
    try:
        # --- شروع اسکن ---
        for r_idx, net in enumerate(valid_ranges, 1):
            range_ip_count = net.num_addresses
            range_str = str(net)
        
            # هدر رنج
            print(f"{Colors.HEADER}>>> Scanning Range [{r_idx}/{total_range_count}]: {range_str}{Colors.ENDC}")
        
            for ip_idx, ip in enumerate(net, 1):
            
                # --- [جدید] بررسی وضعیت کیبورد ---
                if check_keyboard_input():
                    break # اگر Ctrl+C زده شد، از حلقه آی‌پی‌ها بپر بیرون
            
                # --- [جدید] حلقه توقف (Pause Loop) ---
                while IS_PAUSED:
                    time.sleep(0.5) # صبر کن تا کاربر 's' بزند
                    if check_keyboard_input(): # شاید در حالت پوز Ctrl+C بزند
                        if STOP_REQUESTED: break
            
                if STOP_REQUESTED: break # خروج کامل از رنج

                ip_str = str(ip)
                global_ip_counter += 1
            
                # محاسبه درصدها
                pct_range = int((ip_idx / range_ip_count) * 100)
                pct_total = int((global_ip_counter / total_global_ips) * 100)
            
                # تابع آپدیت خط وضعیت
                def update_status(stage, msg, color=Colors.BLUE):
                    # فرمت: [Total: 5%] [Rng: 10%] IP | 1. Config > 2. Msg
                    prefix = f"[{pct_total}%] [Rng:{pct_range}%] {ip_str:<14}"
                    # پاک کردن خط و چاپ
                    sys.stdout.write(f"\r{prefix} | {color}{msg}{Colors.ENDC}" + " "*10)
                    sys.stdout.flush()

                # --- 1. لاگ: ساخت کانفیگ ---
                update_status(1, "1. Config Gen...", Colors.BLUE)
                try:
                    cfg = create_scan_config(base, ip_str, host, port)
                    with open(TEMP_CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(cfg, f, indent=2)
                except Exception as e:
                    update_status(1, "Config Fail", Colors.FAIL)
                    continue

                # --- 2. لاگ: استارت هسته ---
                update_status(2, "2. Starting Core...", Colors.WARNING)
                proc = subprocess.Popen([XRAY_PATH, "-config", TEMP_CONFIG_FILE], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=si)
            
                # --- 3. لاگ: چک پورت ---
                update_status(3, "3. Port Check...", Colors.WARNING)
                port_open = False
                for _ in range(15): # 1.5s
                    try:
                        with socket.create_connection(('127.0.0.1', SOCKS_PORT), timeout=0.1):
                            port_open = True; break
                    except: time.sleep(0.1)
                
                if port_open:
                    # --- 4. لاگ: پینگ ---
                    update_status(4, "4. Pinging...", Colors.CYAN)
                    try:
                        t1 = time.time()
                        proxies = {'http': f'socks5h://127.0.0.1:{SOCKS_PORT}', 'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'}
                        requests.get(TEST_URL, proxies=proxies, timeout=3, verify=False)
                        delay = int((time.time()-t1)*1000)
                    
                        # --- 5. لاگ: iPerf ---
                        update_status(5, f"5. iPerf ({dur}s)...", Colors.HEADER)
                        sp, lo, msg = run_iperf_task(iperf_cmd, dur)
                    
                        if sp > 0 or (lo < 100 and msg == "OK"):
                            # موفقیت
                            final_msg = f"✅ Delay:{delay}ms | Speed:{sp}Mbps | Loss:{lo}%"
                            print(f"\r[{pct_total}%] [Rng:{pct_range}%] {ip_str:<14} | {Colors.GREEN}{final_msg}{Colors.ENDC}" + " "*5)
                            results.append({"ip": ip_str, "real_delay": delay, "speed_mbps": sp, "packet_loss": lo})
                        else:
                            # شکست iPerf
                            print(f"\r[{pct_total}%] [Rng:{pct_range}%] {ip_str:<14} | {Colors.FAIL}❌ iPerf Fail ({msg}){Colors.ENDC}" + " "*5)
                        
                    except Exception:
                        # شکست پینگ
                        print(f"\r[{pct_total}%] [Rng:{pct_range}%] {ip_str:<14} | {Colors.FAIL}❌ No Connection{Colors.ENDC}" + " "*5)
                else:
                    # شکست پورت
                    print(f"\r[{pct_total}%] [Rng:{pct_range}%] {ip_str:<14} | {Colors.FAIL}❌ Xray Core Fail{Colors.ENDC}" + " "*5)

                if proc:
                    proc.terminate()
                    proc.wait()

            if STOP_REQUESTED:
                print(f"\n{Colors.WARNING}⚠️  Stopping Scan Logic...{Colors.ENDC}")
                break     
            # پایان رنج
            print(f"{Colors.GREY}--- Range Finished ---{Colors.ENDC}")
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}⏹  Force Stop (Ctrl+C) Detected! Saving results...{Colors.ENDC}")

    # --- ذخیره نهایی ---
    save_res_final(results)
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    scan()
