🔍 Spider - Herramienta de Análisis de Seguridad

📌 Descripción
Auditoría Web es una herramienta de seguridad en Python diseñada para realizar análisis automatizados en sitios web. Permite detectar vulnerabilidades comunes, recopilar información del servidor y generar informes detallados en PDF con los hallazgos obtenidos.

Esta herramienta es ideal para pentesters, profesionales de ciberseguridad y administradores de sistemas que deseen evaluar la seguridad de sus aplicaciones web de manera eficiente.

⚡ Características Principales
✅ Enumeración de Directorios y Archivos: Busca directorios y scripts expuestos en la aplicación web.
✅ Detección de Vulnerabilidades:

XSS (Cross-Site Scripting): Identifica posibles puntos de inyección de scripts maliciosos.
SQL Injection: Detecta vulnerabilidades de inyección SQL que podrían comprometer la base de datos.
Command Injection: Verifica si el servidor es vulnerable a inyecciones de comandos del sistema.
LFI: Verifica vulnerabilidad web que permite la lectura de archivos locales. 
✅ Escaneo de Puertos y Tecnologías: Obtiene información sobre los servicios y tecnologías que ejecuta el servidor.
✅ Revisión de Encabezados HTTP: Identifica configuraciones inseguras en los headers del sitio web.
✅ Fuerza Bruta y Validación de Credenciales: Pruebas básicas de acceso con diccionarios personalizados.
✅ Generación de Reportes en PDF: Se incluyen tablas detalladas, gráficas de estadísticas y una descripción clara de los hallazgos.


🚀 Instalación
1️⃣ Clona el repositorio:
git clone https://github.com//larm182/Spider.git
cd Spider
2️⃣ Instala las dependencias:
pip install -r requirements.txt
3️⃣ Ejecuta la herramienta:
python auditoria_web.py

📊 Ejemplo de Uso
El usuario puede seleccionar diferentes opciones del menú interactivo, por ejemplo:

Seleccione una opción:

1. Buscar directorios
2. Buscar scripts
3. Verificar puertos
4. Identificar tecnología de la aplicación
5. Revisar encabezados HTTP
6. Realizar pruebas de fuerza bruta
7. Buscar vulnerabilidades XSS
8. Buscar vulnerabilidades SQL Injection
9. Buscar vulnerabilidades de inyección de comandos
10. Buscar vulnerabilidades de local file inclusión
11. Generar reporte en PDF
12. Salir
Tras la ejecución, se generará un informe detallado con los resultados encontrados.

📄 Ejemplo de Reporte

El informe en PDF incluirá:
✔️ Listado de vulnerabilidades encontradas.
✔️ URLs y payloads utilizados en las pruebas.
✔️ Tablas organizadas con la información recopilada.
✔️ Gráficas estadísticas sobre los hallazgos.
✔️ Recomendaciones para mitigar los riesgos.

📌 Requisitos
Python 3.8+
Librerías: requests, beautifulsoup4, fpdf, matplotlib, termcolor, python-nmap, etc.
⚠️ Aviso Legal
Esta herramienta ha sido desarrollada con fines educativos y de seguridad ofensiva ética. El uso indebido en sistemas sin autorización puede ser ilegal. El autor no se hace responsable por el mal uso de esta herramienta.

📊Uso

![image](https://github.com/user-attachments/assets/4a8359c2-559d-4c45-9c43-6fe0a56bb4ef)
![image](https://github.com/user-attachments/assets/759ac103-f97f-4469-9a5b-62e66fcd31ad)
![image](https://github.com/user-attachments/assets/bf220c64-c658-4c89-a59a-fd6a82ff12e2)
![image](https://github.com/user-attachments/assets/edfcc13e-e8f0-4c19-941f-8453c03156cd)
![image](https://github.com/user-attachments/assets/18eeb797-03d7-44ee-933b-ed9fbb3159fc)
![image](https://github.com/user-attachments/assets/20412618-5888-4038-b7b5-e74cf7255432)

📌 Reporte

![image](https://github.com/user-attachments/assets/83507149-ef3d-47b2-8b2c-af9092250c14)
![image](https://github.com/user-attachments/assets/827a374c-5f09-4b31-b335-f0f05aafa8c0)
![image](https://github.com/user-attachments/assets/f677845e-7a0e-4f59-9d42-79a8baa61572)
![image](https://github.com/user-attachments/assets/66c4605f-80f1-4808-9294-456514e872e4)










