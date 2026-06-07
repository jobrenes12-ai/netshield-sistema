# BYUTECH NetShield - Network & Port Scanner

Este repositorio contiene una herramienta profesional de auditoría de redes y ciberseguridad desarrollada bajo la suite de **BYUTECH**. El script permite realizar escaneos pasivos mediante peticiones ARP para identificar dispositivos conectados en la red local y analizar la apertura de puertos críticos propensos a vulnerabilidades.

## Características principales
* **Descubrimiento de Red:** Identificación en tiempo real de direcciones IP y direcciones MAC dentro de un segmento local utilizando paquetes ARP broadcast.
* **Escaneo de Puertos Críticos:** Mapeo automatizado de puertos de red sensibles asociados a vectores comunes de ataque o administración remota (FTP, SSH, HTTP, HTTPS, RDP).
* **Alertas de Seguridad:** Interfaz de consola dinámica con indicadores visuales automáticos cuando se detectan configuraciones expuestas.

## Requisitos del Sistema
* Python 3.x
* Componente Npcap / WinPcap instalado en el sistema operativo.
* Privilegios de Administrador (requerido para la inyección y captura de paquetes de red a nivel de Capa 2).

## Instalación de Dependencias

```bash
pip install scapy