#!/usr/bin/env python3
"""
Generate TRMNL plugin settings YAML with embedded changelog from version.json
"""

import json
import yaml
from pathlib import Path


def get_project_root():
    """Find the project root directory"""
    # Start from the script's directory
    current = Path(__file__).parent

    # If we're in scripts/, go up one level
    if current.name == 'scripts':
        return current.parent

    # Otherwise, assume we're already at root
    return current


def load_version_info():
    """Load version information from version.json"""
    project_root = get_project_root()
    version_file = project_root / 'version.json'

    if not version_file.exists():
        print(f"Warning: version.json not found at {version_file}, using default changelog")
        return []

    with open(version_file, 'r') as f:
        data = json.load(f)

    return data.get('versions', [])


def generate_changelog_html(versions):
    """Generate HTML changelog from version list"""
    if not versions:
        return "No changelog available."

    html_parts = ["<strong>Changelog:</strong><br />"]

    for version in versions:
        version_num = version.get('version', 'Unknown')
        changelog = version.get('changelog', 'No details')
        html_parts.append(f"• <strong>{version_num}:</strong> {changelog}<br />")

    return ''.join(html_parts)


def generate_settings():
    """Generate the complete settings YAML"""

    versions = load_version_info()
    changelog_html = generate_changelog_html(versions)

    settings = [
        {
            'keyname': 'author_info',
            'name': 'About This Plugin',
            'field_type': 'author_bio',
            'description': f"""Keep tabs on every device connected to your home or office network with automatic discovery, smart categorization, and real-time status tracking. Network Devices scans your local network, identifies devices by vendor and type, and displays them with intuitive icons on your TRMNL.<br /><br />Features:<br />• Automatic device detection via arp-scan and nmap<br />• Smart vendor identification from MAC addresses<br />• Offline tracking - see when devices disconnect<br />• Port scanning with customizable labels<br />• Customizable names, icons, and device types<br />• Clean, modern interface with Material Symbols icons<br />• Update notifications<br /><br />Requires a Docker container running on your network (5 min setup). Perfect for monitoring IoT devices, tracking network usage, or keeping an eye on who's connected.<br /><br />{changelog_html}""",
            'github_url': 'https://github.com/ExcuseMi/trmnl-network-devices-plugin',
            'category': 'analytics'
        },
        {
            'keyname': 'device_identifiers',
            'field_type': 'multi_string',
            'name': 'Device Configuration',
            'description': 'Customize device names, vendors, types, icons, or hide specific devices',
            'placeholder': 'MAC=AA:BB:CC:DD:EE:FF;name=Living Room Pi;type=Raspberry Pi;icon=memory',
            'help_text': '<strong>Format:</strong> <code>MAC=xx:xx:xx:xx:xx:xx;name=Device Name;vendor=Vendor;type=Type;icon=icon_name;ports=port:label:port:label;hide=true</code><br /><br /> <strong>All fields are optional.</strong> Use semicolons (;) to separate fields.<br /><br /> <strong>Examples:</strong><br /> • <code>MAC=AA:BB:CC:DD:EE:FF;name=Security Camera;icon=videocam</code><br /> • <code>IP=192.168.1.10;name=Pi-hole;type=Raspberry Pi;icon=memory</code><br /> • <code>MAC=11:22:33:44:55:66;hide=true</code> (hide device)<br /> • <code>MAC=99:88:77:66:55:44;vendor=;type=</code> (clear auto-detected info)<br /> • <code>IP=192.168.1.100;ports=8080=Admin:9000=API</code> (custom port labels for this device)<br /><br /> <strong>Field Reference:</strong><br /> • <strong>MAC/IP:</strong> Device identifier (MAC preferred, use IP if MAC changes)<br /> • <strong>name:</strong> Display name for the device<br /> • <strong>vendor:</strong> Manufacturer (shown in parentheses after type)<br /> • <strong>type:</strong> Device category (e.g., "Smart Speaker", "Camera")<br /> • <strong>icon:</strong> Custom icon name from Material Symbols (see below)<br /> • <strong>ports:</strong> Custom port labels for this device only (format: <code>port=label:port=label</code>)<br /> • <strong>hide:</strong> Set to "true" to hide device from display<br /><br /> <strong>Common Icons:</strong><br /> <code>router</code>, <code>phone_iphone</code>, <code>tablet_mac</code>, <code>laptop_mac</code>, <code>computer</code>, <code>tv</code>, <code>speaker</code>, <code>print</code>, <code>videocam</code>, <code>lightbulb</code>, <code>thermostat</code>, <code>doorbell</code>, <code>memory</code> (Raspberry Pi), <code>nest_remote</code>, <code>cast</code>, <code>smartphone</code>, <code>headphones</code>, <code>sports_esports</code>, <code>videogame_asset</code>, <code>storage</code>, <code>power</code><br /> <a href="https://fonts.google.com/icons" target="_blank" class="underline">Browse all 2,500+ Material Symbols icons</a>',
            'optional': True
        },
        {
            'keyname': 'show_offline_devices',
            'field_type': 'select',
            'name': 'Show Offline Devices',
            'description': 'Show devices that were not found in the most recent network scan',
            'options': [
                {'Yes - Show Offline Devices': 'yes'},
                {'No - Hide Offline Devices': 'no'}
            ],
            'default': 'yes',
            'optional': True
        },
        {
            'keyname': 'show_mac_addresses',
            'field_type': 'select',
            'name': 'Show MAC Addresses',
            'description': 'Display MAC addresses below each device',
            'options': [
                {'Yes - Show MAC addresses': 'yes'},
                {'No - Hide MAC addresses': 'no'}
            ],
            'default': 'no',
            'help_text': 'Useful for identifying devices to configure in Device Configuration above. MAC addresses appear as a third line below the device name and type.',
            'optional': True
        },
        {
            'keyname': 'show_update_notification',
            'field_type': 'select',
            'name': 'Show Update Notification',
            'description': 'Show notification when a new version is available',
            'options': [
                {'Yes - Show update notification': 'yes'},
                {'No - Hide update notification': 'no'}
            ],
            'default': 'yes',
            'help_text': 'When enabled, a small indicator appears in the title bar when a new version of the plugin is released.',
            'optional': True
        },
        {
            'keyname': 'show_ports',
            'field_type': 'select',
            'name': 'Show Open Ports',
            'description': 'Display open ports for each device',
            'options': [
                {'Yes - Show open ports': 'yes'},
                {'No - Hide ports': 'no'}
            ],
            'default': 'no',
            'help_text': 'Shows which ports are open on each device. Requires port scanning to be enabled in your Docker container (ENABLE_PORT_SCAN=true). Ports appear as small badges below device information.',
            'optional': True
        },
        {
            'keyname': 'port_display_mode',
            'field_type': 'select',
            'name': 'Port Display Mode',
            'description': 'How to display port information',
            'options': [
                {'Number + Label (e.g., "22 (SSH)")': 'both'},
                {'Label Only (e.g., "SSH")': 'label'},
                {'Number Only (e.g., "22")': 'number'}
            ],
            'default': 'both',
            'help_text': 'Choose how port information is displayed:<br />• <strong>Number + Label:</strong> Shows port number with service name (e.g., "22 (SSH)")<br />• <strong>Label Only:</strong> Shows only service name (e.g., "SSH"), falls back to number if no label<br />• <strong>Number Only:</strong> Shows only port numbers (e.g., "22")',
            'optional': True
        },
        {
            'keyname': 'port_labels',
            'field_type': 'string',
            'name': 'Global Port Labels',
            'description': 'Override default port labels (comma-separated)',
            'placeholder': '22=SSH,80=Web,443=Secure Web,3389=Remote Desktop',
            'help_text': '<strong>Format:</strong> <code>port=label,port=label,...</code><br /><br /><strong>Default labels are already provided for 50+ common ports including:</strong><br />• <strong>22</strong>=SSH, <strong>80</strong>=HTTP, <strong>443</strong>=HTTPS, <strong>3389</strong>=RDP, <strong>5900</strong>=VNC<br />• <strong>3306</strong>=MySQL, <strong>5432</strong>=PostgreSQL, <strong>27017</strong>=MongoDB, <strong>6379</strong>=Redis<br />• <strong>1883</strong>=MQTT, <strong>8123</strong>=Home Assistant, <strong>32400</strong>=Plex<br />• And many more...<br /><br /><strong>Use this setting to:</strong><br />• Override default labels (e.g., <code>80=Web Server</code> instead of "HTTP")<br />• Add labels for custom ports (e.g., <code>9876=My App</code>)<br /><br /><strong>For per-device port labels,</strong> use the Device Configuration setting with the <code>ports</code> field.',
            'optional': True
        }
    ]

    return settings


def main():
    project_root = get_project_root()
    settings = generate_settings()

    # Ensure data directory exists
    data_dir = project_root / 'data'
    data_dir.mkdir(exist_ok=True)

    # Output to data/settings.yml
    output_file = data_dir / 'settings.yml'
    with open(output_file, 'w') as f:
        yaml.dump(settings, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"✓ Generated {output_file}")
    print(f"  Project root: {project_root}")
    print(f"  Contains {len(settings)} settings")

    # Also output to stdout for inspection
    print("\n" + "=" * 60)
    print("Generated Settings:")
    print("=" * 60)
    print(yaml.dump(settings, default_flow_style=False, allow_unicode=True, sort_keys=False))


if __name__ == '__main__':
    main()