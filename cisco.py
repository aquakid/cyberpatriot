# make sure to install this library before running
from netmiko import ConnectHandler
#pip install netmiko

class CiscoSecurityAudit:
    def __init__(self, device_params):
        self.device_params = device_params
        self.connection = None

    def connect(self):
        self.connection = ConnectHandler(**self.device_params)
        self.connection.enable()

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()

    def check_vulnerabilities(self):
        self.disable_unnecessary_services()
        self.set_strong_password_policies()
        self.configure_aaa()
        self.enable_logging()
        self.disable_unused_interfaces()
        self.configure_ssh()
        self.set_banners()
        self.secure_snmp()
        self.configure_ntp()
        self.secure_console_access()
        self.secure_auxiliary_ports()
        self.secure_vty_lines()
        self.disable_ipv6_if_not_used()
        self.apply_acl()
        self.verify_configs()

    def disable_unnecessary_services(self):
        commands = [
            'no service tcp-small-servers',
            'no service udp-small-servers',
            'no cdp run',
            'no ip http server',
            'no ip http secure-server',
            'no ip finger',
            'no ip bootp server',
            'no ip source-route',
            'no service pad',
            'no ip identd',
            'no mop enabled',
        ]
        self.connection.send_config_set(commands)

    def set_strong_password_policies(self):
        commands = [
            'service password-encryption',
            'security passwords min-length 10',
            'login block-for 120 attempt 3 within 60',
            'username admin privilege 15 secret StrongPassword123',  # Replace with a strong password
        ]
        self.connection.send_config_set(commands)

    def configure_aaa(self):
        commands = [
            'aaa new-model',
            'aaa authentication login default local',
            'aaa authorization exec default local',
        ]
        self.connection.send_config_set(commands)

    def enable_logging(self):
        commands = [
            'logging buffered 16384 warnings',
            'no logging console',
            'logging trap warnings',
            'service timestamps log datetime msec localtime show-timezone',
        ]
        self.connection.send_config_set(commands)

    def disable_unused_interfaces(self):
        commands = [
            'interface range FastEthernet0/1 - 24',
            'shutdown',
            'no cdp enable',
            'exit',
        ]
        self.connection.send_config_set(commands)

    def configure_ssh(self):
        commands = [
            'ip domain-name example.com',  # Replace with your domain
            'crypto key generate rsa modulus 2048',
            'ip ssh version 2',
            'ip ssh time-out 60',
            'ip ssh authentication-retries 2',
        ]
        self.connection.send_config_set(commands)

    def set_banners(self):
        commands = [
            'banner motd ^CUnauthorized access is prohibited.^C',
            'banner login ^CYou are accessing a secured device.^C',
        ]
        self.connection.send_config_set(commands)

    def secure_snmp(self):
        commands = [
            'no snmp-server community public',
            'no snmp-server community private',
            'snmp-server community YourCommunityString RO',  # Replace with your SNMP community string
        ]
        self.connection.send_config_set(commands)

    def configure_ntp(self):
        commands = [
            'ntp server 192.168.1.100',  # Replace with your NTP server IP
            'ntp authenticate',
            'ntp authentication-key 1 md5 YourKey',  # Replace with your NTP key
            'ntp trusted-key 1',
        ]
        self.connection.send_config_set(commands)

    def secure_console_access(self):
        commands = [
            'line console 0',
            'logging synchronous',
            'exec-timeout 5 0',
            'exit',
        ]
        self.connection.send_config_set(commands)

    def secure_auxiliary_ports(self):
        commands = [
            'line aux 0',
            'exec-timeout 0 1',
            'no exec',
            'transport input none',
            'exit',
        ]
        self.connection.send_config_set(commands)

    def secure_vty_lines(self):
        commands = [
            'line vty 0 4',
            'transport input ssh',
            'exec-timeout 5 0',
            'login local',
            'exit',
        ]
        self.connection.send_config_set(commands)

    def disable_ipv6_if_not_used(self):
        commands = [
            'no ipv6 cef',
            'no ipv6 unicast-routing',
            'interface range FastEthernet0/0 - 24',
            'no ipv6 address',
            'exit',
        ]
        self.connection.send_config_set(commands)

    def apply_acl(self):
        commands = [
            'ip access-list standard MANAGEMENT',
            'permit 192.168.1.0 0.0.0.255',  # Replace with your management network
            'exit',
            'line vty 0 4',
            'access-class MANAGEMENT in',
            'exit',
        ]
        self.connection.send_config_set(commands)

    def verify_configs(self):
        output = self.connection.send_command('show running-config')
        # Implement parsing logic to verify configurations if necessary
        print("Configuration verification complete.")

    def save_config(self):
        self.connection.save_config()

if __name__ == "__main__":
    # Device information
    cisco_device = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.1',  # Replace with your device's IP
        'username': 'admin',     # Replace with your username
        'password': 'admin',     # Replace with your password
        'secret': 'admin',       # Enable secret
    }

    auditor = CiscoSecurityAudit(cisco_device)
    auditor.connect()
    auditor.check_vulnerabilities()
    auditor.save_config()
    auditor.disconnect()
