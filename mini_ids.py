#!/usr/bin/env python3
import argparse
import time
from collections import defaultdict
from scapy.all import sniff, TCP, IP, Raw, wrpcap

# Anomali tespiti için IP bazlı istekleri tutacağımız sözlük
packet_counts = defaultdict(int)
start_time = time.time()

# Global değişkenler
ALERT_THRESHOLD = 100
OUTPUT_PCAP = None

def process_packet(packet):
    """Her yakalanan paket için çağrılan analiz fonksiyonu."""
    global start_time, packet_counts, OUTPUT_PCAP
    
    is_suspicious = False # Paketi PCAP'a kaydedip kaydetmeyeceğimize karar veren bayrak
    
    # 1. Anomali Tespiti (SYN Flood veya Hızlı Port Taraması)
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1
        
        # Eşiği aşan paketleri anında şüpheli işaretle
        if packet_counts[src_ip] > ALERT_THRESHOLD:
            is_suspicious = True
        
        # Her saniye başı sayaçları terminale bas ve sıfırla
        current_time = time.time()
        if current_time - start_time >= 1.0:
            for ip, count in packet_counts.items():
                if count > ALERT_THRESHOLD:
                    print(f"[!] ANOMALİ TESPİT EDİLDİ: {ip} adresinden saniyede {count} paket geldi! (Olası Tarama/Flood)")
            packet_counts.clear()
            start_time = current_time

    # 2. Şifresiz HTTP Trafiğinde Hassas Veri Yakalama
    if packet.haslayer(Raw):
        try:
            # Paketin içeriğini okumaya çalış (Payload)
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Basit bir HTTP POST veya GET isteğinde parola parametreleri arama
            if "POST" in payload or "GET" in payload:
                payload_lower = payload.lower()
                if "password=" in payload_lower or "pwd=" in payload_lower or "login=" in payload_lower:
                    print(f"[*] HASSAS VERİ YAKALANDI (Şifresiz Trafik) -> Kaynak: {packet[IP].src}")
                    print(f"    Payload Özeti: {payload[:100].strip()}...\n")
                    is_suspicious = True
        except Exception:
            pass

    # Eğer paket şüpheliyse ve bir çıkış dosyası belirtilmişse kaydet
    if is_suspicious and OUTPUT_PCAP:
        # append=True sayesinde mevcut dosyaya ekleme yapar, RAM'i doldurmaz
        wrpcap(OUTPUT_PCAP, packet, append=True)

def main():
    parser = argparse.ArgumentParser(description="Mini IDS: Ağ Trafiği İzleyici ve Anomali Uyarıcısı")
    parser.add_argument("-i", "--interface", help="Dinlenecek ağ arayüzü (örn: eth0, wlan0)", default=None)
    parser.add_argument("-t", "--threshold", type=int, default=100, help="Saniye başına paket uyarı eşiği (Varsayılan: 100)")
    parser.add_argument("-o", "--output", help="Şüpheli paketlerin kaydedileceği PCAP dosyası (örn: alerts.pcap)", default=None)
    
    args = parser.parse_args()
    
    global ALERT_THRESHOLD, OUTPUT_PCAP
    ALERT_THRESHOLD = args.threshold
    OUTPUT_PCAP = args.output

    print(f"[*] Mini IDS başlatıldı... (Arayüz: {args.interface if args.interface else 'Varsayılan'})")
    print(f"[*] Uyarı Eşiği: Saniyede {ALERT_THRESHOLD} paket.")
    if OUTPUT_PCAP:
        print(f"[*] Şüpheli paketler şuraya kaydedilecek: {OUTPUT_PCAP}")
    print("[*] Şifresiz HTTP kimlik bilgileri ve ağ anomalileri izleniyor.")
    print("[!] Çıkış yapmak için CTRL+C'ye basın.\n")

    try:
        sniff(iface=args.interface, prn=process_packet, store=False)
    except PermissionError:
        print("[X] Kritik Hata: Paket dinleme işlemi için yönetici (root/Administrator) yetkilerine sahip olmanız gerekir.")
        print("    Linux: 'sudo python3 mini_ids.py' şeklinde çalıştırın.")
        print("    Windows: Komut İstemini (CMD) 'Yönetici olarak çalıştır' ile açın.")
    except KeyboardInterrupt:
        print("\n[*] IDS güvenli bir şekilde durduruldu.")

if __name__ == "__main__":
    main()
