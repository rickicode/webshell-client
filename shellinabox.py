#!/usr/bin/python3

import socket
import sys, os, subprocess, signal, re, ipaddress, time, subprocess, urllib.request, json, base64, tempfile
from urllib.parse import urlparse

def get_ip_from_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        print("Cannot resolve domain %s to an IP address. Exiting." % (domain,))
        sys.exit(1)

def monitor_daemon(inactivity_interval, identity_file):
	orig_pid = os.getpid()
	try:
		pid = os.fork()
		if pid > 0:
			return
	except OSError as e:
		print("Fork #1 failed: %d (%s)" % (e.errno, e.strerror))
		sys.exit(1)

	os.chdir("/")
	os.setsid()
	os.umask(0)

	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError as e:
		print("Fork #2 failed: %d (%s)" % (e.errno, e.strerror))
		sys.exit(1)
	
	# if identity_file != "":
	# 	time.sleep(1)
	# 	os.unlink(identity_file)

	try:
		while True:
			proc = subprocess.Popen('timeout %d strace -e write=1,2 -e trace=write -p %d' % (inactivity_interval, orig_pid), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			proc.poll()
			counter = 0
			for line in proc.stderr.readlines():
				counter += 1
			if(counter <= 3):
				os.kill(orig_pid, signal.SIGKILL)
				sys.exit(0)
	except Exception as e:
		pass

	sys.exit(0)


if __name__ == "__main__":
	peer_info = sys.argv[1] if len(sys.argv) > 1 else ""
	peer_desc = urlparse(peer_info)
	peer_parts = peer_desc.query.split('/')

	peer_port = int(os.environ['SSH_PORT']) if 'SSH_PORT' in os.environ else 22
	peer_login = os.environ['USERNAME'] if 'USERNAME' in os.environ else 'root'
	peer_ip = os.environ['DEFAULT_IP'] if 'DEFAULT_IP' in os.environ else '127.0.0.1'
	allowed_networks = os.environ['ALLOWED_NETWORKS'] if 'ALLOWED_NETWORKS' in os.environ else '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7'
	inactivity_interval = int(os.environ['INACTIVITY_INTERVAL']) if 'INACTIVITY_INTERVAL' in os.environ else 500
	is_vault_enabled = True if 'VAULT_ENABLED' in os.environ and os.environ['VAULT_ENABLED'] == 'true' else False
	vault_url = os.environ["VAULT_URL"] if is_vault_enabled else ""
	vault_value = os.environ["VAULT_VALUE"] if is_vault_enabled else ""

	print("Welcome to a Webshell SSH powered by NETQ.ME (https://netq.me)")

	if peer_info == "" or peer_desc.query == "":
		def sigalrm_handler(signum, frame):
			print("\nInactivity timeout is reached (%d seconds). Exit." % inactivity_interval)
			sys.exit(1)

		signal.signal(signal.SIGALRM, sigalrm_handler)
		signal.setitimer(signal.ITIMER_REAL, inactivity_interval)
		try:
			peer_ip_candidate = input("Enter host ip to connect (Default: %s): " % peer_ip)
			peer_port_candidate = input("Enter port to connect (Default: %d): " % peer_port)
			peer_login_candidate = input("Login: (Default: %s): " % peer_login)
			peer_parts = []
			peer_parts.append(peer_ip_candidate)
			peer_parts.append(peer_port_candidate)
			peer_parts.append(peer_login_candidate)
		finally:
			signal.signal(signal.SIGALRM, signal.SIG_DFL)
			signal.setitimer(signal.ITIMER_REAL, 0)

	length = len(peer_parts)

	if length > 0:
		try:
			ipaddress.ip_address(peer_parts[0])
			peer_ip = peer_parts[0]
		except:
			peer_ip = get_ip_from_domain(peer_parts[0])
			print("Domain %s resolved to %s" % (peer_parts[0], peer_ip))

	if length > 1:
		try:
			peer_port_candidate = int(peer_parts[1])
			if 0 < peer_port_candidate < 65535:
				peer_port = peer_port_candidate
			else:
				print("Port %d doesn't match to a valid port range [1, 65535]. Exit" % (peer_port_candidate,))
				sys.exit(1)
		except ValueError:
			pass

	if length > 2:
		peer_login_candidate = peer_parts[2]
		if re.match("^[a-z0-9_-]{3,16}$", peer_login_candidate):
			peer_login = peer_login_candidate

	identity_file = ""
	if length > 3:
		try:
			privkey = base64.b64decode(peer_parts[3]).decode('utf-8')
		except (base64.binascii.Error, UnicodeDecodeError) as e:
			print("Error: Failed to decode base64:", e)
			sys.exit(1)
		if "RSA" in privkey:
				privkey_path = os.path.join("/tmp", "privkey")
				if os.path.exists(privkey_path):
					os.unlink(privkey_path)
				# Write the privkey content to the file
				with open(privkey_path, "w") as f:
					f.write(privkey)
				# Set permissions to 600 for security
				os.chmod(privkey_path, 0o600)
				identity_file = privkey_path
				print("Using public key authentication...")
				# print(f"Public key is saved to {privkey_path}")

	allowed_networks = list(map(lambda x: ipaddress.ip_network(x.strip()), allowed_networks.split(",")))
	ipInNetworks = False
	for net in allowed_networks:
		if ipaddress.ip_address(peer_ip) in net:
			ipInNetworks = True
			break

	if not ipInNetworks:
		print("IP %s does not relate to allowed networks." % (peer_ip))
		sys.exit(1)

	print("SSH Connection to %s@%s#%i will be opened..." % (peer_login, peer_ip, peer_port))
	monitor_daemon(inactivity_interval, identity_file)
	identity_args = []
	if identity_file != "":
		identity_args = ["-i", identity_file]
		# print("Identity file is set to %s" % (identity_file,))
	os.execv("/usr/bin/ssh", ["/usr/bin/ssh"] + identity_args + ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", str(peer_port), "%s@%s" % (peer_login, peer_ip)])
