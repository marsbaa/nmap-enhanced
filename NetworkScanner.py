import os
import shlex
import shutil
import subprocess
from OutputParse import OutputParser


class NMapRunner:

    def __init__(self):
        """
        Create a Nmap executor
        """
        self.nmap_report_file = None
        found_sudo = shutil.which('sudo', mode=os.F_OK | os.X_OK)
        if not found_sudo:
            raise ValueError(f"SUDO is missing")
        self.sudo = found_sudo
        found_nmap = shutil.which('nmap', mode=os.F_OK | os.X_OK)
        if not found_nmap:
            raise ValueError(f"NMAP is missing")
        self.nmap = found_nmap

    def scan(
            self,
            *,
            hosts: str,
            sudo: bool = True
    ):
        command = []
        if sudo:
            command.append(self.sudo)
        command.append(self.nmap)
        command.extend(__NMAP__FLAGS__)
        command.append(hosts)
        completed = subprocess.run(
            command,
            capture_output=True,
            shell=False,
            check=True
        )
        completed.check_returncode()
        args, data = OutputParser.parse_nmap_xml(
            completed.stdout.decode('utf-8'))
        return args, data, completed.stderr


# Convert the args for proper usage on the CLI
NMAP_HOME_NETWORK_DEFAULT_FLAGS = {
    '-n': 'Never do DNS resolution',
    '-sS': 'TCP SYN scan, recommended',
    '-p-': 'All ports',
    '-sV': 'Probe open ports to determine service/version info',
    '-O': 'OS Probe. Requires sudo/ root',
    '-T4': 'Aggressive timing template',
    '-PE': 'Enable this echo request behavior. Good for internal networks',
    '--version-intensity 5': 'Set version scan intensity. Default is 7',
    '--disable-arp-ping': 'No ARP or ND Ping',
    '--max-hostgroup 20': 'Hostgroup (batch of hosts scanned concurrently) size',
    '--min-parallelism 10': 'Number of probes that may be outstanding for a host group',
    '--osscan-limit': 'Limit OS detection to promising targets',
    '--max-os-tries 1': 'Maximum number of OS detection tries against a target',
    '-oX -': 'Send XML output to STDOUT, avoid creating a temp file'
}
__NMAP__FLAGS__ = shlex.split(" ".join(NMAP_HOME_NETWORK_DEFAULT_FLAGS.keys()))
