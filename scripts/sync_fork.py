#!/usr/bin/env python3

import os
import sys
import re
import shutil
import zipfile
import requests
import yaml
from pathlib import Path


# Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;36m'
    NC = '\033[0m'


def log(message, color=None):
    if color:
        print(f"{color}{message}{Colors.NC}")
    else:
        print(message)


def main():
    # Determine project root (handle running from root or scripts)
    current_dir = Path.cwd()

    if current_dir.name == 'scripts':
        project_root = current_dir.parent
    else:
        project_root = current_dir

    # Paths
    archive_dir = project_root / "archive"
    data_dir = project_root / "data"
    env_file = project_root / "plugins.env"

    log("=== TRMNL Plugin Fork Sync ===\n", Colors.BLUE)

    # Check for API key
    api_key = os.environ.get('TRMNL_API_KEY')
    if not api_key:
        log("Error: TRMNL_API_KEY environment variable is not set", Colors.RED)
        log("Usage: export TRMNL_API_KEY='user_xxxxx'")
        sys.exit(1)

    # Load environment variables
    if not env_file.exists():
        log(f"Error: plugins.env not found at {env_file}", Colors.RED)
        sys.exit(1)

    env_vars = {}
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key] = value.strip('"\'')

    recipe_id = env_vars.get('RECIPE_ID')
    fork_id = env_vars.get('FORK_ID')
    user_id = env_vars.get('USER_ID')

    if not recipe_id:
        log("Error: RECIPE_ID not set in plugins.env", Colors.RED)
        sys.exit(1)

    if not user_id:
        log("Error: USER_ID not set in plugins.env", Colors.RED)
        sys.exit(1)

    # Determine download source
    download_id = fork_id if fork_id else recipe_id
    source_type = "FORK" if fork_id else "RECIPE"

    log(f"Step 1: Downloading archive from {source_type} {download_id}", Colors.YELLOW)

    # Clean and create archive directory
    if archive_dir.exists():
        shutil.rmtree(archive_dir)
    archive_dir.mkdir(parents=True)

    # Download archive
    download_file = archive_dir / "download.zip"
    response = requests.get(
        f"https://trmnl.com/api/plugin_settings/{download_id}/archive",
        headers={"Authorization": f"Bearer {api_key}"}
    )

    if response.status_code != 200:
        log(f"✗ Download failed with HTTP {response.status_code}", Colors.RED)
        sys.exit(1)

    with open(download_file, 'wb') as f:
        f.write(response.content)

    log("✓ Downloaded archive\n", Colors.GREEN)

    # Extract archive
    log("Step 2: Extracting archive", Colors.YELLOW)
    with zipfile.ZipFile(download_file, 'r') as zip_ref:
        zip_ref.extractall(archive_dir)

    download_file.unlink()

    log("✓ Extracted files:", Colors.GREEN)
    for item in archive_dir.iterdir():
        print(f"  {item.name}")
    print()

    # Merge options if exists
    options_file = data_dir / "options.yml"
    settings_file = archive_dir / "settings.yml"

    if options_file.exists():
        log("Step 3: Merging options.yml into settings.yml", Colors.YELLOW)

        if not settings_file.exists():
            log("Error: settings.yml not found in archive", Colors.RED)
            sys.exit(1)

        # Load both YAML files
        with open(settings_file, 'r') as f:
            settings = yaml.safe_load(f)

        with open(options_file, 'r') as f:
            options = yaml.safe_load(f)

        # Replace custom_fields with options
        if options and 'custom_fields' in settings:
            settings['custom_fields'] = options

            # Write back
            with open(settings_file, 'w') as f:
                yaml.dump(settings, f, default_flow_style=False,
                          allow_unicode=True, sort_keys=False)

            log("✓ Applied options from data/options.yml\n", Colors.GREEN)
    else:
        log("Step 3: No data/options.yml found, skipping merge\n", Colors.YELLOW)

    # Update settings
    log("Step 4: Updating settings.yml", Colors.YELLOW)

    if not settings_file.exists():
        log("Error: settings.yml not found in archive", Colors.RED)
        sys.exit(1)

    # Load and modify
    with open(settings_file, 'r') as f:
        settings = yaml.safe_load(f)

    # Update ID
    settings['id'] = int(recipe_id)

    # Remove (Fork) from name
    if 'name' in settings:
        settings['name'] = settings['name'].replace(' (Fork)', '')

    # Write back
    with open(settings_file, 'w') as f:
        yaml.dump(settings, f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)

    log(f"✓ Updated ID to {recipe_id} and removed (Fork) from title\n", Colors.GREEN)

    # Replace USER_ID in all liquid files
    log("Step 5: Replacing USER_ID in template files", Colors.YELLOW)

    liquid_files = list(archive_dir.glob("*.liquid"))
    replaced_count = 0

    for liquid_file in liquid_files:
        content = liquid_file.read_text()

        # Replace patterns like "owner_user_id = -1234" or "user.id == -1234"
        # Handles both positive and negative numbers
        new_content = re.sub(
            r'(owner_user_id\s*=\s*)-?\d+',
            rf'\g<1>{user_id}',
            content
        )
        new_content = re.sub(
            r'(user\.id\s*==\s*)-?\d+',
            rf'\g<1>{user_id}',
            new_content
        )

        if new_content != content:
            liquid_file.write_text(new_content)
            replaced_count += 1
            log(f"  ✓ Updated {liquid_file.name}", Colors.GREEN)

    if replaced_count > 0:
        log(f"✓ Replaced USER_ID in {replaced_count} file(s)\n", Colors.GREEN)
    else:
        log("✓ No USER_ID replacements needed\n", Colors.GREEN)

    # Create upload archive
    log("Step 6: Creating upload archive", Colors.YELLOW)
    upload_file = project_root / f"private_plugin_{recipe_id}.zip"

    if upload_file.exists():
        upload_file.unlink()

    with zipfile.ZipFile(upload_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in archive_dir.iterdir():
            if file.is_file():
                zipf.write(file, file.name)

    file_size = upload_file.stat().st_size
    log(f"✓ Created archive ({file_size} bytes)\n", Colors.GREEN)

    # Upload to recipe
    log(f"Step 7: Uploading to RECIPE {recipe_id}", Colors.YELLOW)

    with open(upload_file, 'rb') as f:
        files = {'file': ('archive.zip', f, 'application/zip')}
        response = requests.post(
            f"https://trmnl.com/api/plugin_settings/{recipe_id}/archive",
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "trmnl-sync-script"
            },
            files=files
        )

    if response.status_code == 200:
        log("✓ Upload successful!\n", Colors.GREEN)
        log(f"Dashboard: https://trmnl.com/plugin_settings/{recipe_id}/edit\n", Colors.GREEN)

        # Clean up
        log("Cleaning up...", Colors.YELLOW)
        upload_file.unlink()
        log("✓ Done!", Colors.GREEN)
    else:
        log(f"✗ Upload failed with HTTP {response.status_code}", Colors.RED)
        print(f"Response: {response.text}")
        sys.exit(1)


if __name__ == "__main__":
    main()