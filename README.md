# WebReaper 🕵️‍♂️
WebReaper es una herramienta rápida de reconocimiento web que identifica tecnologías y rutas ocultas en aplicaciones HTTP/HTTPS usando WhatWeb y Gobuster


Herramienta ofensiva de reconocimiento web automatizado.

## Descripción

Escanea automáticamente objetivos con puertos web (80/443) usando:

- [x] WhatWeb: para fingerprint del servidor web.
- [x] Gobuster: para descubrir rutas ocultas.
- [x] Resumen limpio y exportado como `.txt`.

## Uso

```bash
autowebscan <IP_o_dominio> <puertos_abiertos>
