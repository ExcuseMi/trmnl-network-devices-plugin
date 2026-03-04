#!/usr/bin/env python3
import requests
import re
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def load_plugin_config():
    """Load plugin IDs from plugins.env file in ../script directory"""
    config = {
        'plugin_ids': [],
        'section_title': '🚀 Plugin Statistics',
        'images_dir': 'assets/plugin-images'
    }

    # Try multiple possible locations for plugins.env
    possible_paths = [
        '../script/plugins.env',  # From scripts/ directory looking into script/
        'plugins.env',            # Current directory
        './plugins.env',          # Current directory explicitly
        '../plugins.env',         # Parent directory
    ]

    env_file_path = None
    for path in possible_paths:
        if os.path.exists(path):
            env_file_path = path
            print(f"📁 Found plugins.env at: {path}")
            break

    if not env_file_path:
        print("⚠️  plugins.env file not found in any of the expected locations:")
        for path in possible_paths:
            print(f"   - {path}")
        print("Using default configuration.")
        return config

    try:
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        if key == 'PLUGIN_IDS':
                            config['plugin_ids'] = [pid.strip() for pid in value.split(',') if pid.strip()]
                        elif key == 'SECTION_TITLE':
                            config['section_title'] = value
                        elif key == 'IMAGES_DIR':
                            config['images_dir'] = value
    except Exception as e:
        print(f"⚠️  Error reading plugins.env from {env_file_path}: {e}")
        print("Using default configuration.")

    return config


def download_image(url: str, save_path: str, max_retries=3):
    """Download an image from URL and save it locally with retry logic"""
    for attempt in range(max_retries):
        try:
            headers = {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            new_content = response.content
            new_hash = hashlib.md5(new_content).hexdigest()

            # Check if file exists and compare hash
            if os.path.exists(save_path):
                with open(save_path, 'rb') as f:
                    old_hash = hashlib.md5(f.read()).hexdigest()

                if old_hash == new_hash:
                    print(f"  ↪ Unchanged: {os.path.basename(save_path)}")
                    return True

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Save the image
            with open(save_path, 'wb') as f:
                f.write(new_content)

            print(f"  ✓ Updated: {os.path.basename(save_path)}")
            return True

        except requests.RequestException as e:
            if attempt < max_retries - 1:
                print(f"  ⚠️  Retry {attempt + 1}/{max_retries - 1} for {os.path.basename(save_path)}")
            else:
                print(f"  ✗ Failed to download {os.path.basename(save_path)} after {max_retries} attempts: {e}")
                return False

    return False


def get_image_extension(url: str):
    """Extract file extension from URL"""
    parsed = urlparse(url)
    path = parsed.path
    _, ext = os.path.splitext(path)
    # Default to .png if no extension found
    return ext if ext else '.png'


def fetch_plugin_data(plugin_id: str, max_retries=3):
    """Fetch plugin data from TRMNL API with retry logic"""
    url = f"https://usetrmnl.com/recipes/{plugin_id}.json"

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                print(f"  ⚠️  Retry {attempt + 1}/{max_retries - 1} for plugin data")
            else:
                print(f"  ✗ HTTP Error fetching plugin data after {max_retries} attempts: {e}")
                return None
        except ValueError as e:
            print(f"  ✗ JSON parsing error for plugin {plugin_id}: {e}")
            print(f"  Response content: {response.text[:200]}...")
            return None

    return None


def process_plugin_images(plugin_id: str, plugin_data: dict, images_dir: str):
    """Download plugin images and return local paths"""
    if not plugin_data:
        return None

    plugin = plugin_data.get('data', {})

    # Get image URLs
    icon_url = plugin.get('icon_url', '')
    screenshot_url = plugin.get('screenshot_url', '')

    local_paths = {
        'icon': None,
        'screenshot': None
    }

    download_success = True

    # Download icon
    if icon_url:
        icon_ext = get_image_extension(icon_url)
        icon_filename = f"{plugin_id}_icon{icon_ext}"
        icon_path = os.path.join(images_dir, icon_filename)

        if download_image(icon_url, icon_path):
            local_paths['icon'] = icon_path
        else:
            download_success = False

    # Download screenshot
    if screenshot_url:
        screenshot_ext = get_image_extension(screenshot_url)
        screenshot_filename = f"{plugin_id}_screenshot{screenshot_ext}"
        screenshot_path = os.path.join(images_dir, screenshot_filename)

        if download_image(screenshot_url, screenshot_path):
            local_paths['screenshot'] = screenshot_path
        else:
            download_success = False

    return local_paths if download_success else None


def generate_plugin_section(data, plugin_id: str, image_paths: dict):
    """Generate markdown section for a plugin"""
    if not data:
        markdown = f"""
## 🔒 Plugin ID: {plugin_id}

**Status**: ⏳ Not yet published on TRMNL or API unavailable

This plugin is configured but either hasn't been published to the TRMNL marketplace yet or the API is temporarily unavailable.

**Plugin URL**: https://usetrmnl.com/recipes/{plugin_id}

---
"""
        return markdown

    plugin = data.get('data', {})

    if not plugin:
        markdown = f"""
## 🔒 Plugin ID: {plugin_id}

**Status**: ⏳ Plugin data incomplete

The plugin exists but data is not available yet. This usually means it's very new or still being processed.

**Plugin URL**: https://usetrmnl.com/recipes/{plugin_id}

---
"""
        return markdown

    # Use local image paths or fallback to original URLs
    icon_path = image_paths.get('icon') if image_paths else plugin.get('icon_url', '')
    screenshot_path = image_paths.get('screenshot') if image_paths else plugin.get('screenshot_url', '')

    name = plugin.get('name', 'Unknown Plugin')
    description = plugin.get('author_bio', {}).get('description', 'No description available')

    markdown = f"""
## <img src="{icon_path}" alt="{name} icon" width="32"/> [{name}](https://usetrmnl.com/recipes/{plugin_id})

![Installs](https://trmnl-badges.gohk.xyz/badge/installs?recipe={plugin_id}) ![Forks](https://trmnl-badges.gohk.xyz/badge/forks?recipe={plugin_id})

![{name} screenshot]({screenshot_path})

### Description
{description}

---
"""
    return markdown


def update_readme(plugin_sections: str, section_title: str):
    """Update README.md with plugin statistics"""
    try:
        with open('README.md', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        content = "# Project README\n\n"

    start_marker = "<!-- PLUGIN_STATS_START -->"
    end_marker = "<!-- PLUGIN_STATS_END -->"

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    new_content = f"{start_marker}\n## {section_title}\n\n*Last updated: {timestamp}*\n\n{plugin_sections}\n{end_marker}"

    if start_marker in content and end_marker in content:
        pattern = f"{re.escape(start_marker)}.*?{re.escape(end_marker)}"
        updated_content = re.sub(pattern, new_content, content, flags=re.DOTALL)
    else:
        updated_content = content + "\n\n" + new_content + "\n"

    with open('README.md', 'w') as f:
        f.write(updated_content)


def main():
    """Main execution function"""
    config = load_plugin_config()
    plugin_ids = config['plugin_ids']
    section_title = config['section_title']
    images_dir = config['images_dir']

    if not plugin_ids:
        print("❌ No plugin IDs found in plugins.env")
        return

    print(f"📋 Tracking {len(plugin_ids)} plugins: {', '.join(plugin_ids)}")
    print(f"📁 Images will be saved to: {images_dir}\n")

    plugin_sections = []
    total = len(plugin_ids)

    published_plugins = 0
    unpublished_plugins = 0
    failed_downloads = []

    for idx, plugin_id in enumerate(plugin_ids, 1):
        print(f"🔍 [{idx}/{total}] Processing plugin: {plugin_id}")

        data = fetch_plugin_data(plugin_id)

        image_paths = None
        if data and data.get('data'):
            image_paths = process_plugin_images(plugin_id, data, images_dir)
            if image_paths:
                published_plugins += 1
                print(f"  ✓ Plugin processed successfully")
            else:
                published_plugins += 1
                failed_downloads.append(plugin_id)
                print(f"  ⚠️  Plugin found but image downloads failed")
        else:
            unpublished_plugins += 1
            if data and not data.get('data'):
                print(f"  ⚠️  Plugin exists but data is incomplete")
            else:
                print(f"  ⏳ Plugin not published yet or API error")

        section = generate_plugin_section(data, plugin_id, image_paths)
        plugin_sections.append(section)
        print()

    all_sections = "\n".join(plugin_sections)
    update_readme(all_sections, section_title)

    print("✅ README.md updated successfully with plugin statistics!")
    print(f"📊 Summary:")
    print(f"   Published plugins: {published_plugins}")
    print(f"   Unpublished/Error plugins: {unpublished_plugins}")
    if failed_downloads:
        print(f"   ⚠️  Failed image downloads for: {', '.join(failed_downloads)}")
    print(f"📸 Images saved to: {images_dir}/")


if __name__ == "__main__":
    main()