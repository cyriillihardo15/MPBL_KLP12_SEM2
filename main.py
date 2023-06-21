from flask import Flask, render_template, request, redirect, url_for, session, flash
import socket
import threading
import time
import os


app = Flask(__name__)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/portfolio')
def portfolio():
    return render_template("portfolio.html")


@app.route('/project')
def project():
    return render_template("project.html")


@app.route('/portscan', methods=['POST'])
def portscan():
    ports = [7, 20, 21, 22, 23, 25, 53, 69, 80, 102, 110, 135,
             137, 139, 143, 443, 465, 587, 593, 993, 995, 3306, 8080]

    port_info = {
        7: "Echo", 20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 69: "TFTP", 80: "HTTP", 102: "Iso-tsap", 110: "POP3",
        135: "Microsoft EPMAP", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 465: "SMTPS", 587: "SMTP", 593: "Microsoft DCOM",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 8080: "HTTP Proxy",
    }
    open_ports = []
    closed_ports = []

    url = request.form['url']
    special_chars = ["http://", "https://", "/"]
    for char in special_chars:
        url = url.replace(char, "")
    host = socket.gethostbyname(url)

    start_port = request.form['start']
    end_port = request.form['end']

    single_port = request.form['single_port']

    def scan_port(host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)

    def scan_range(host, start_port, end_port):
        for port in range(start_port, end_port+1):
            t = threading.Thread(target=scan_port, args=(host, port))
            t.start()
            time.sleep(0.01)

    def scan_list(host):
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                service = port_info.get(port)
                open_ports.append(port)
            else:
                closed_ports.append(port)

    def scan_single(host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)

    if start_port.strip() == "" and end_port.strip() == "":
        if single_port.isdigit():
            scan_single(host, int(single_port))
        else:
            scan_list(host)
    elif start_port.isdigit() and end_port.isdigit():
        scan_range(host, int(start_port), int(end_port))
    elif single_port.isdigit():
        scan_single(host, int(single_port))

    return render_template("project.html", open=open_ports, closed=closed_ports, info=port_info, url=url, start=start_port, end=end_port, single_port=single_port, host=host)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
    # app.run(debug=True, port=8080)
    # app.run(debug=True, port=os.getenv("PORT", default=8080))
