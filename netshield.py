import scapy.all as scapy
import socket
import sys

def banner():
    print("="*60)
    print("        BYUTECH NetShield - Network & Port Scanner        ")
    print("="*60)

def scan_network(ip_range):
    """
    Escanea la red local usando peticiones ARP para descubrir dispositivos conectados.
    """
    print(f"\n[*] Escaneando la red en el rango: {ip_range}...")
    
    # Crea una petición ARP para mapear IPs y MAC addresses
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    # Envía el paquete y recibe las respuestas
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
        
    return devices

def scan_ports(ip, ports_to_scan):
    """
    Verifica si los puertos críticos seleccionados están abiertos en un dispositivo.
    """
    open_ports = []
    for port in ports_to_scan:
        # Crea un socket TCP clásico para probar la conexión
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Tiempo de espera rápido
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main():
    banner()
    
    # Rango por defecto para escanear
    target_network = "192.168.1.1/24" 
    
    # Puertos críticos vectores de ataque (21:FTP, 22:SSH, 80:HTTP, 443:HTTPS, 3389:RDP)
    critical_ports = [21, 22, 80, 443, 3389]
    
    try:
        discovered_devices = scan_network(target_network)
        
        print("\n[+] DISPOSITIVOS ENCONTRADOS EN LA RED:")
        print(f"{'IP Address':<15} | {'MAC Address':<17} | {'Puertos Críticos Abiertos'}")
        print("-" * 70)
        
        for device in discovered_devices:
            open_ports = scan_ports(device["ip"], critical_ports)
            
            if open_ports:
                ports_str = ", ".join(str(p) for p in open_ports) + " <-- ¡Alerta de Seguridad!"
            else:
                ports_str = "Ninguno (Seguro)"
                
            print(f"{device['ip']:<15} | {device['mac']:<17} | {ports_str}")
            
    except KeyboardInterrupt:
        print("\n[-] Escaneo cancelado por el usuario.")
        sys.exit()

if __name__ == "__main__":
    main()