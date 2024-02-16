#!/usr/bin/python

'''
	Simple HTTP server with shortcuts and tweaks
'''
import http.server
import socketserver
import os
import sys
import subprocess
import cgi
import warnings

#Suppress deprecated cgi warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cgi")
os.system("clear")

#Important banner
print("""
 -----------------------------------------------------------------------------------------------
               _  _ ___ ___ ___     ____ _  _ _  _    ____ ____ _  _ ____ ____ 
               |__|  |   |  |__]    |__| |  |  \/     [__  |__/ |  | |___ |__/ 
               |  |  |   |  |       |  | |__| _/\_    ___] |  \  \/  |___ |  \ 
                                                                               
 -----------------------------------------------------------------------------------------------
                                                                                     DannyDB@~>
""")

#Default port
PORT = 80
if len(sys.argv) == 2:
	PORT = int(sys.argv[1])


#Direct access files  <- ** ADD YOUR OWN SHORTCUTS HEARE **
SHORTCUTS = {
	#------------------For windows------------------------------------------
	'/mm.exe':'~/git/mimikatz64.exe',								#Mimikatz
	'/mm32.exe':'~/git/mimikatz32.exe',								#Mimikatz32
	#------------------Recon scripts----------------------------------------
	'/recon.sh':'~/bin/recon.sh',									#Linux reconnaissance script
	'/recon.ps1':'~/bin/recon.ps1',									#Windows reconnaissance script
}

#Files to replace IP
IP_REPLACE=[
	'/recon.sh',
	'/recon.ps1'
]

#Gets the IP on the tun0 interface
def ip_tun0():
	try:
		resultado = subprocess.check_output(["ip", "addr", "show", "tun0"]).decode("utf-8")
		lineas = resultado.split("\n")
		for linea in lineas:
			if "inet" in linea and "tun0" in linea:
				# Extraer la dirección IP
				partes = linea.split()
				direccion_ip = partes[1].split("/")[0]
				return direccion_ip
	except subprocess.CalledProcessError:
		pass
	return "0.0.0.0"


class Handler(http.server.SimpleHTTPRequestHandler):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, directory='.', **kwargs)

	def do_GET(self):
		if not os.path.isfile("."+self.path) and self.path in SHORTCUTS:
			file_path=os.path.expanduser(SHORTCUTS[self.path])
			print(" [*] Danny -> Enviando fichero: ", file_path)
			self.send_file(file_path)
		else:
			super().do_GET()

	def do_POST(self):
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		# Get the file name
		f_name="uploaded_file"
		content_disposition = self.headers.get('Content-Disposition', '')
		if content_disposition:
			_, params = cgi.parse_header(content_disposition)
			f_name = params.get('filename')
		# Save the file to the current directory
		filename = os.path.join(os.getcwd(), f_name)
		with open(filename, 'wb') as file:
			file.write(post_data)

		self.send_response(200)
		self.end_headers()
		self.wfile.write(b'Received!!')
		print(" [*] File received: ", filename)

	def send_file(self, file_path):
		try:
			with open(file_path, 'rb') as file:
				# Set headers for content type
				self.send_response(200)
				self.send_header('Content-type', 'application/octet-stream')
				self.send_header('Content-Disposition', 'attachment; filename=' + os.path.basename(file_path))
				self.end_headers()
				# To embed tun0 IP
				if self.path in IP_REPLACE:
					file_content = file.read().decode('utf-8')
					# Replace
					file_content = file_content.replace('{IP_KALI}',ip_tun0())
					self.wfile.write(file_content.encode('utf-8'))
				else:
					# Send the file content to the client
					self.wfile.write(file.read())
		except Exception as e:
			self.send_error(500, str(e))


with socketserver.TCPServer(("", PORT), Handler) as httpd:
	print(" [>] Listening on port ", PORT)
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		print("\n [>] Closing the server...")
		httpd.server_close()
		sys.exit(0)