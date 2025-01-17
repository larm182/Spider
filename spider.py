#!/usr/bin/python
#-*- coding: utf-8 -*-
#Autor: Luis Angel Ramirez Mendoza
#______________________________________________________________________________________________________________________
#Verificar https://github.com/1N3/IntruderPayloads/blob/master/FuzzLists para generar una lista mayor
import requests
from bs4 import BeautifulSoup
import socket
import nmap
import os
import subprocess
from fpdf import FPDF
import tempfile 
from io import BytesIO
import matplotlib.pyplot as plt
from termcolor import colored

# Función para buscar directorios
def find_directories(url, wordlist):
    print("\n--- Buscando directorios ---")
    found = []
    with open(wordlist, 'r') as file:
        for line in file:
            directory = line.strip()
            full_url = f"{url}{directory}"
            try:
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200:
                    print(f"[ENCONTRADO] {full_url}")
                    found.append(full_url)
            except:
                pass
    return found

# Función para buscar scripts
def find_scripts(url, wordlist):
    print("\n--- Buscando scripts ---")
    found_scripts = []
    with open(wordlist, 'r') as file:
        for line in file:
            item = line.strip()
            full_url = f"{url}/{item}"
            try:
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200 and item.endswith(('.js', '.php', '.html', '.txt', '.log')):
                    print(f"[SCRIPT ENCONTRADO] {full_url}")
                    found_scripts.append(full_url)
            except:
                pass
    return found_scripts

# Función para escanear puertos comunes
def check_ports(target_host):
    print("\n--- Buscando Puertos ---")
        # Escaneo con Nmap
    try:
        comando = f"nmap -Pn -sV -p 1-10000 -O {target_host}"
        resultado_crudo = subprocess.check_output(comando, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Falló el escaneo: {e}")
        resultado_crudo = None

    if resultado_crudo:
        # Procesamiento de la salida de Nmap
        datos_procesados = []
        lines = resultado_crudo.splitlines()
        puerto_seccion = False

        for line in lines:
            if line.startswith("PORT"):
                puerto_seccion = True
                continue

            if puerto_seccion and line.strip():
                partes = line.split()
                if len(partes) >= 3:
                    puerto_estado = partes[0]
                    estado = partes[1]
                    servicio = " ".join(partes[2:])
                    datos_procesados.append({
                        "Puerto": puerto_estado,
                        "Estado": estado,
                        "Servicio": servicio
                    })
    #datos_procesados.append((puerto_estado, estado, servicio))

    # Impresión en consola
    print(f"\n{'-' * 50}")
    print(f"Host escaneado: {target_host}")
    print(f"Número de puertos encontrados: {len(datos_procesados)}")
    print(f"{'-' * 50}")
    print(f"{'Puerto':<15}{'Estado':<15}{'Servicio':<20}")
    print(f"{'-' * 50}")
      
    for resultado in datos_procesados:
        print(f"{resultado['Puerto']:<15}{resultado['Estado']:<15}{resultado['Servicio']:<20}")
    print(f"{'-' * 50}")
    return datos_procesados



# Función para identificar la tecnología de la aplicación
def identify_technology(url):
    print("\n--- Identificando tecnología de la aplicación ---")
    tech_info = {}
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        if 'Server' in headers:
            tech_info['Server'] = headers['Server']
            print(f"Servidor detectado: {headers['Server']}")
        
        if 'X-Powered-By' in headers:
            tech_info['X-Powered-By'] = headers['X-Powered-By']
            print(f"Tecnología detectada: {headers['X-Powered-By']}")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find_all('meta', {'name': 'generator'}):
            generator = soup.find('meta', {'name': 'generator'})
            tech_info['CMS'] = generator.get('content', 'Desconocido')
            print(f"CMS detectado: {generator.get('content', 'Desconocido')}")
        
    except Exception as e:
        print(f"Error al identificar tecnología: {e}")
    return tech_info

# Función para revisar encabezados HTTP
def check_http_headers(url):
    print("\n--- Revisando encabezados HTTP ---")
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers
        print(f"Encabezados HTTP para {url}:")
        for header, value in headers.items():
            print(f"{header}: {value}")
        return headers
    except Exception as e:
        print(f"Error al obtener encabezados: {e}")
        return None

# Función para realizar pruebas de fuerza bruta o validación de credenciales
def brute_force(url, username_list, password_list):
    print("\n--- Realizando pruebas de fuerza bruta ---")
    found_credentials = []
    for username in username_list:
        for password in password_list:
            try:
                response = requests.post(url, data={'username': username, 'password': password}, timeout=5)
                if "incorrect" not in response.text.lower():
                    print(f"[CREDENCIALES ENCONTRADAS] Usuario: {username}, Contraseña: {password}")
                    found_credentials.append((username, password))
            except Exception as e:
                print(f"Error en fuerza bruta: {e}")
    return found_credentials

# Función para escanear vulnerabilidades XSS
def scan_xss(url, wordlist):
    print("\n--- Probando XSS ---")
    vulnerable = []
    with open(xss_wordlist, 'r') as file:
        for payload in file:
            payload = payload.strip()
            try:
                response = requests.get(f"{url}{payload}", timeout=5)
                if payload in response.text:
                    print(f"[VULNERABLE] XSS detectado en {url} con payload {payload}")
                    vulnerable.append(payload)
            except Exception as e:
                print(f"Error al probar XSS: {e}")
    return vulnerable

# Función para escanear vulnerabilidades SQL Injection
def scan_sql_injection(url, wordlist):
    print("\n--- Probando inyección SQL ---")
    vulnerable = []
    with open(sql_wordlist, 'r') as file:
        for payload in file:
            payload = payload.strip()
            try:
                response = requests.get(f"{url}{payload}", timeout=5)
                if "SQL" in response.text or "syntax" in response.text:
                    print(f"[VULNERABLE] Inyección SQL detectada en {url} con payload {payload}")
                    vulnerable.append(payload)
            except Exception as e:
                print(f"Error al probar SQLi: {e}")
    return vulnerable

# Función para escanear vulnerabilidades de inyección de comandos
def scan_command_injection(url, cmd_wordlist):
    print("\n--- Probando inyección de comandos ---")
    vulnerable = []
    with open(cmd_wordlist, 'r') as file:
        for payload in file:
            payload = payload.strip()
            try:
                response = requests.get(f"{url}{payload}", timeout=5)
                #print("estoy aca")
                if any(keyword in response.text.lower() for keyword in ["uid=", "root", "administrator", "systeminfo", "directory", "microsoft", "windows", "win32", "nt", "build", "version","volume", "system", "user", "administrator"]):
                    print(f"[VULNERABLE] Inyección de comandos detectada en {url} con payload {payload}")
                    vulnerable.append(payload)
            except Exception as e:
                print(f"Error al probar inyección de comandos: {e}")
    return vulnerable


# Función para Local File Inclusión
def scan_xss(url, lfi_wordlist):
    print("\n--- Probando Local File Inclusión ---")
    vulnerable = []
    with open(lfi_wordlist, 'r') as file:
        for payload in file:
            payload = payload.strip()
            try:
                response = requests.get(f"{url}{payload}", timeout=5)
                if payload in response.text:
                    print(f"[VULNERABLE] Local File Inclusión detectado en {url} con payload {payload}")
                    vulnerable.append(payload)
            except Exception as e:
                print(f"Error al probar Local File Inclusión: {e}")
    return vulnerable


# Función para generar la gráfica de vulnerabilidades y agregarla al PDF
def generate_vulnerability_graph(results, pdf):
    vulnerabilities = [
        ("XSS", len(results["Vulnerabilidades XSS"])),
        ("SQL Injection", len(results["Vulnerabilidades SQL Injection"])),
        ("Inyección de Comandos", len(results["Vulnerabilidades de inyección de comandos"])),
        ("Directorios Encontrados", len(results["Directorios encontrados"])),
        ("Scripts Encontrados", len(results["Scripts encontrados"])),
        ("Local File Inclusion", len(results["Vulnerabilidades de local file inclusion"])),
    ]
    
    labels = [v[0] for v in vulnerabilities]
    counts = [v[1] for v in vulnerabilities]

    # Generar la gráfica
    plt.figure(figsize=(10,6))
    plt.bar(labels, counts, color='blue')
    plt.xlabel('Tipo de Vulnerabilidad')
    plt.ylabel('Cantidad Encontrada')
    plt.title('Estadísticas de Vulnerabilidades Encontradas')
    plt.tight_layout()

    # Guardar la gráfica en un archivo temporal
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:
        image_path = temp_file.name
        plt.savefig(image_path)
        plt.close()  # Cerrar la figura

    # Insertar la gráfica en el PDF
    pdf.image(image_path, x=30, y=40, w=150)

# Función para generar el reporte PDF
def generate_report(results):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Arial", size=12)

        # Título
        pdf.cell(200, 10, txt="Reporte de Spider", ln=True, align='C')
        
        # Introducción
        pdf.set_font("Arial", style='I', size=10)
        pdf.multi_cell(0, 10, """
        Este reporte resume los hallazgos de Spider realizada sobre el sitio web objetivo.
        Se han realizado diferentes pruebas de seguridad para identificar posibles vulnerabilidades como:
        - Vulnerabilidades XSS (Cross-site Scripting)
        - Inyección SQL
        - Inyección de comandos
        - Local file inclusión
        - Revisión de puertos y encabezados HTTP
        - Identificación de la tecnología utilizada
        A continuación se presentan las vulnerabilidades encontradas junto con estadísticas y detalles de los hallazgos.
        SITIO: """ + target_url)

         #Escaner de puertos
        if results["Puertos abiertos"]:
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, f"Informe de Escaneo de Puertos - {target_host}", ln=True)
            pdf.ln(10)
            pdf.set_font("Arial", size=10)
            pdf.cell(40, 10, "Puerto", 1, 0, 'C')
            pdf.cell(40, 10, "Estado", 1, 0, 'C')
            pdf.cell(105, 10, "Servicio", 1, 1, 'C')

            pdf.set_font("Arial", size=9)
            for datos_procesados in results["Puertos abiertos"]:
                pdf.cell(40, 10, str(datos_procesados['Puerto']), 1, 0, 'C')
                pdf.cell(40, 10, datos_procesados['Estado'], 1, 0, 'C')
                pdf.cell(105, 10, datos_procesados['Servicio'], 1, 1, 'C')

        #Tecnologia detectada
        if results["Tecnología detectada"]:
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, f"Tecnologia Detectada - {target_url}", ln=True)
            pdf.ln(2)
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 10, f" Resultado: - {results['Tecnología detectada']}")

         #Encabezado
        if results["Encabezados HTTP"]:            
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, f"Los Encabezados HTTP", ln=True)
            pdf.ln(2)
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 10, f" Resultado: - {results['Encabezados HTTP']}")
        #Directorios
        if results["Directorios encontrados"]:            
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, f"Los Directorios Encontrados:", ln=True)
            pdf.ln(2)
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 10, f" Resultado: - {results['Directorios encontrados']}")
        #Programas
        if results["Scripts encontrados"]:            
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, f"Los Script Encontrados:", ln=True)
            pdf.ln(2)
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 10, f" Resultado: - {results['Scripts encontrados']}")

        # Gráfica de vulnerabilidades
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, "Estadísticas de Vulnerabilidades Encontradas", ln=True, align='C')
        
        # Espacio antes de la gráfica
        pdf.ln(20)
        
        generate_vulnerability_graph(results, pdf)

        # Tabla de estadísticas
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, txt="Estadísticas de Vulnerabilidades Encontradas", ln=True)
        pdf.set_font("Arial", size=10)
        
        # Crear tabla para las estadísticas
        pdf.cell(90, 10, "Vulnerabilidad", 1, 0, 'C')
        pdf.cell(40, 10, "Cantidad", 1, 1, 'C')
        
        pdf.cell(90, 10, "XSS", 1, 0, 'C')
        pdf.cell(40, 10, str(len(results["Vulnerabilidades XSS"])), 1, 1, 'C')
        
        pdf.cell(90, 10, "SQL Injection", 1, 0, 'C')
        pdf.cell(40, 10, str(len(results["Vulnerabilidades SQL Injection"])), 1, 1, 'C')
        
        pdf.cell(90, 10, "Comando Inyección", 1, 0, 'C')
        pdf.cell(40, 10, str(len(results["Vulnerabilidades de inyección de comandos"])), 1, 1, 'C')

        pdf.cell(90, 10, "Local File Inclusion", 1, 0, 'C')
        pdf.cell(40, 10, str(len(results["Vulnerabilidades de local file inclusion"])), 1, 1, 'C')
        
        pdf.cell(90, 10, "Directorios Encontrados", 1, 0, 'C')
        pdf.cell(40, 10, str(len(results["Directorios encontrados"])), 1, 1, 'C')

        pdf.cell(90, 10, "Scripts Encontrados", 1, 0, 'C')
        pdf.cell(40, 10, str(len(results["Scripts encontrados"])), 1, 1, 'C')


        # Sección de vulnerabilidades XSS
        if results["Vulnerabilidades XSS"]:
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, "Vulnerabilidades XSS Encontradas", ln=True)
            pdf.set_font("Arial", size=10)
            pdf.cell(90, 10, "URL", 1, 0, 'C')
            pdf.cell(90, 10, "Payload", 1, 1, 'C')

            for xss in results["Vulnerabilidades XSS"]:
                pdf.cell(90, 10, target_url, 1, 0, 'C')
                pdf.cell(90, 10, xss, 1, 1, 'C')  # XSS no requiere payload específico

        # Sección de vulnerabilidades SQL Injection
        if results["Vulnerabilidades SQL Injection"]:
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, "Vulnerabilidades SQL Injection Encontradas", ln=True)
            pdf.set_font("Arial", size=10)
            pdf.cell(90, 10, "URL", 1, 0, 'C')
            pdf.cell(90, 10, "Payload", 1, 1, 'C')

            for sql in results["Vulnerabilidades SQL Injection"]:
                pdf.cell(90, 10, target_url, 1, 0, 'C')
                pdf.cell(90, 10, sql, 1, 1, 'C')  # SQL Injection no requiere payload específico

        # Sección de vulnerabilidades de inyección de comandos
        if results["Vulnerabilidades de inyección de comandos"]:
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, "Vulnerabilidades de Inyección de Comandos Encontradas", ln=True)
            pdf.set_font("Arial", size=10)
            pdf.cell(90, 10, "URL", 1, 0, 'C')
            pdf.cell(90, 10, "Payload", 1, 1, 'C')

            for command in results["Vulnerabilidades de inyección de comandos"]:
                pdf.cell(90, 10, target_url, 1, 0, 'C')
                pdf.cell(90, 10, command, 1, 1, 'C')  # Comando de inyección no requiere payload específico

        # Sección de Vulnerabilidades de local file inclusion
        if results["Vulnerabilidades de local file inclusion"]:
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(0, 10, "Vulnerabilidades de local file inclusion Encontradas", ln=True)
            pdf.set_font("Arial", size=10)
            pdf.cell(90, 10, "URL", 1, 0, 'C')
            pdf.cell(90, 10, "Payload", 1, 1, 'C')

            for lfi in results["Vulnerabilidades de local file inclusion"]:
                pdf.cell(90, 10, target_url, 1, 0, 'C')
                pdf.cell(90, 10, lfi, 1, 1, 'C')  # Comando de inyección no requiere payload específico

        # Conclusión
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, """
        Conclusión:
        El reporte presentado muestra una visión general de las vulnerabilidades encontradas en el sitio web objetivo.
        Las vulnerabilidades como XSS, SQL Injection, y de inyección de comandos representan riesgos críticos para la seguridad de la aplicación.
        Se recomienda tomar medidas para mitigar estos riesgos y realizar auditorías adicionales para asegurar la protección continua de los sistemas.
        """)
        
        pdf.output("_Reporte_Spider.pdf")
        print("\n_[INFO] Reporte generado: Reporte_Spider.pdf")
    
    except Exception as e:
        print(f"[ERROR] Ocurrió un problema al generar el reporte: {e}")
# Menú principal
def main_menu():
    print("\n--- Menú de Principal ---")
    # El texto "SPIDER" en ASCII art
    spider_art = '''
      SSSSS   PPPPP  III  DDDD   EEEEE  RRRRR
     S        P   P   I   D   D  E      R   R
      SSS     PPPPP   I   D   D  EEEE   RRRRR
         S    P       I   D   D  E      R R
     SSSSS    P      III  DDDD   EEEEE  R  RR
    '''

    # La araña en ASCII art
    spider_image = '''
            (
             )
            (
       /\  .-"""-.  /\
      //\\/  ,,,  \//\\
      |/\| ,;;;;;, |/\|
      //\\\;-"""-;///\\
     //  \/   .   \/  \\       @Larm182, version 1.0
    (| ,-_| \ | / |_-, |)     https://github.com/larm182
      //`__\.-.-./__`\\        
     //    /   "   \    \\
    (|   /   (     )   \   |)
      \\\|   |/\/\/\|   |////
       \ |   |      |   | /
        \|   |      |   |/
         |   |      |   |
         |   |      |   |
    '''

    # Imprimir el letrero con la araña
    print(colored(spider_image, 'yellow'))
    print(colored(spider_art, 'cyan'))
    print()
    print(colored("1. Buscar directorios",'red'))
    print(colored("2. Buscar scripts",'red'))
    print(colored("3. Verificar puertos",'red'))
    print(colored("4. Identificar tecnología de la aplicación",'red'))
    print(colored("5. Revisar encabezados HTTP",'red'))
    print(colored("6. Realizar pruebas de fuerza bruta",'red'))
    print(colored("7. Buscar vulnerabilidades XSS",'red'))
    print(colored("8. Buscar vulnerabilidades SQL Injection",'red'))
    print(colored("9. Buscar vulnerabilidades de inyección de comandos",'red'))
    print(colored("10. Buscar vulnerabilidades de local file inclusión",'red'))
    print(colored("11. Generar reporte en PDF",'red'))
    print(colored("12. Salir",'red'))
    return input("Seleccione una opción: ")

if __name__ == "__main__":
    target_url = input("Ingrese la URL objetivo (con http/https): ")
    target_host = input("Ingrese la dirección IP o dominio de la aplicación para verificar puertos: ")
    results = {
        "Directorios encontrados": [],
        "Scripts encontrados": [],
        "Puertos abiertos": [],
        "Tecnología detectada": {},
        "Encabezados HTTP": [],
        "Pruebas de fuerza bruta": [],
        "Vulnerabilidades XSS": [],
        "Vulnerabilidades SQL Injection": [],
        "Vulnerabilidades de inyección de comandos": [],
        "Vulnerabilidades de local file inclusion": [],
    }

    # Lista de usuarios y contraseñas para fuerza bruta (debe ser proporcionada por el usuario)
    username_list = ["admin", "user", "test"]
    password_list = ["123456", "password", "admin123"]

    # Wordlists para XSS, SQL y Comando de inyección
    xss_wordlist = "xss_wordlist.txt"
    sql_wordlist = "sql_wordlist.txt"
    cmd_wordlist = "command_injection_wordlist.txt"
    lfi_wordlist = "lfi_wordlist.txt"

    while True:
        choice = main_menu()
        if choice == "1":
            wordlist_path = input("Ingrese la ruta del wordlist de directorios: ")
            results["Directorios encontrados"] = find_directories(target_url, wordlist_path)
        elif choice == "2":
            wordlist_path = input("Ingrese la ruta del wordlist de scripts: ")
            results["Scripts encontrados"] = find_scripts(target_url, wordlist_path)
        elif choice == "3":
            results["Puertos abiertos"] = check_ports(target_host)
        elif choice == "4":
            results["Tecnología detectada"] = identify_technology(target_url)
        elif choice == "5":
            results["Encabezados HTTP"] = check_http_headers(target_url)
        elif choice == "6":
            results["Pruebas de fuerza bruta"] = brute_force(target_url, username_list, password_list)
        elif choice == "7":
            results["Vulnerabilidades XSS"] = scan_xss(target_url, xss_wordlist)
        elif choice == "8":
            results["Vulnerabilidades SQL Injection"] = scan_sql_injection(target_url, sql_wordlist)
        elif choice == "9":
            results["Vulnerabilidades de inyección de comandos"] = scan_command_injection(target_url, cmd_wordlist)
        elif choice == "10":
            results["Vulnerabilidades de local file inclusion"] = scan_command_injection(target_url, lfi_wordlist)
        elif choice == "11":
            generate_report(results)
        elif choice == "12":
            print("Saliendo...")
            break
        else:
            print("Opción no válida, intente nuevamente.")

