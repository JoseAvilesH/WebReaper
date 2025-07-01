#!/usr/bin/env python3

import subprocess
import sys
import re
from rich import print
from rich.console import Console
from datetime import datetime

console = Console()

def banner():
    console.print("""
[bold green]
██████╗ ██╗   ██╗████████╗ ██████╗ ██╗    ██╗███████╗██████╗ 
██╔══██╗██║   ██║╚══██╔══╝██╔══██╗██║    ██║██╔════╝██╔══██╗
██████╔╝██║   ██║   ██║   ██████╔╝██║ █╗ ██║█████╗  ██████╔╝
██╔═══╝ ██║   ██║   ██║   ██╔═══╝ ██║███╗██║██╔══╝  ██╔═══╝ 
██║     ╚██████╔╝   ██║   ██║     ╚███╔███╔╝███████╗██║     
╚═╝      ╚═════╝    ╚═╝   ╚═╝      ╚══╝╚══╝ ╚══════╝╚═╝     
                                                                  
    [bold cyan]Escaneo Web Automatizado | Autor: MrMoore[/bold cyan]
[/bold green]
""")


def ejecutar_comando(comando, titulo=None, filtrar=None):
    if titulo:
        console.print(f"\n[bold cyan][*] {titulo}[/bold cyan]")
    resultado = subprocess.run(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    salida = resultado.stdout
    if filtrar:
        return "\n".join([l for l in salida.splitlines() if filtrar(l)])
    return salida.strip()


def tiene_puertos_web(puertos):
    return any(p in ["80", "443"] for p in puertos.split(","))


def ejecutar_whatweb(url):
    comando = f"whatweb --no-color {url}"
    salida_raw = ejecutar_comando(comando, "Fingerprint con WhatWeb")
    return parsear_whatweb(salida_raw)


def parsear_whatweb(salida_raw):
    parsed = {}
    partes = salida_raw.split(" ", 1)
    parsed["URL"] = partes[0].strip() if partes else "N/A"

    if len(partes) > 1:
        plugins = partes[1].split(", ")
        for p in plugins:
            if "[" in p:
                nombre, valor = p.split("[", 1)
                parsed[nombre.strip()] = valor.strip("[]")
            else:
                parsed[p.strip()] = "Sí"

    resumen = "\n"
    resumen += f"URL: {parsed.get('URL', 'N/A')}\n"
    if "Title" in parsed:
        resumen += f"Título: {parsed['Title']}\n"
    if "HTTPServer" in parsed:
        resumen += f"Servidor Web: {parsed['HTTPServer']}\n"
    if "Apache" in parsed:
        resumen += f"Apache: {parsed['Apache']}\n"
    if "Country" in parsed:
        resumen += f"Ubicación IP: {parsed['Country']}\n"
    if "Email" in parsed:
        resumen += f"Contacto: {parsed['Email']}\n"
    if "HTML5" in parsed:
        resumen += "Tecnologías detectadas: HTML5\n"

    return resumen.strip()


def ejecutar_gobuster(url):
    diccionario = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    extensiones = "php,txt,html,php.bak"
    comando = f"gobuster dir -u {url} -w {diccionario} -t 20 -x {extensiones} -q"
    return ejecutar_comando(comando, "Enumeración de rutas con Gobuster", lambda l: "Status: 200" in l or "Status: 403" in l)


def guardar_resumen_txt(ip, resumen_txt):
    nombre_archivo = f"resumen_autowebscan_{ip.replace('.', '_')}.txt"
    with open(nombre_archivo, 'w') as f:
        f.write(resumen_txt)
    console.print(f"\n[bold green][✔] Resumen guardado en:[/bold green] [bold]{nombre_archivo}[/bold]")


def main():
    banner()

    if len(sys.argv) != 3:
        print("Uso: autowebscan.py <IP_o_dominio> <puertos_abiertos>")
        print("Ejemplo: autowebscan.py 192.168.1.100 22,80,443")
        sys.exit(1)

    objetivo = sys.argv[1]
    puertos = sys.argv[2]
    url = f"http://{objetivo}"

    if not tiene_puertos_web(puertos):
        console.print("[yellow][!] No hay puertos web (80/443). Abortando.[/yellow]")
        sys.exit(0)

    fingerprint = ejecutar_whatweb(url)
    rutas = ejecutar_gobuster(url)

    # Construir resumen
    resumen_txt = f"""
=== RESUMEN DE ESCANEO WEB ===
Fecha/Hora: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Objetivo: {objetivo}

--- WhatWeb ---
{fingerprint}

--- Rutas encontradas por Gobuster ---
{rutas.strip()}
"""

    # Mostrar y guardar resumen
    console.print("\n[bold green]=== RESUMEN FINAL ===[/bold green]")
    console.print(resumen_txt)
    guardar_resumen_txt(objetivo, resumen_txt)


if __name__ == "__main__":
    main()
