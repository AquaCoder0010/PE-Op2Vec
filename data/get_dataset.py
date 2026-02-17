import os
import shutil
from pathlib import Path
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel

# Setup Paths using Pathlib
CWD = Path.cwd()

REPO_URL = "https://github.com/iosifache/DikeDataset.git"
REPO_NAME = "DikeDataset"

WINDOWS_PATH = Path("/home/aqua/mount-file/temp-sda3/Windows")
WINDOWS_PE_COUNT = 10_000

BASE_DIR = CWD / REPO_NAME
DEST_DIR = CWD / "data" / "raw"

# Create destination if it doesn't exist
DEST_DIR.mkdir(parents=True, exist_ok=True)

BENIGN_SRC = BASE_DIR / "files" / "benign"
MALWARE_SRC = BASE_DIR / "files" / "malware"

console = Console()

def run_task():
    console.print(Panel.fit("[bold blue]Processing DikeDataset[/bold blue]", border_style="cyan"))

    if not BASE_DIR.exists():
        console.print(f"[yellow]Cloning repository: {REPO_URL}...[/yellow]")
        exit_code = os.system(f"git clone {REPO_URL}")
        
        if exit_code != 0:
            console.print("[bold red]Error: Failed to clone repository.[/bold red]")
            return
    else:
        console.print("[green]Repository already exists. Skipping clone.[/green]")


    sources = [BENIGN_SRC, MALWARE_SRC]
    
    for src in sources:
        if not src.exists():
            console.print(f"[bold red]Warning: Source path {src} not found![/bold red]")
            continue

        files = list(src.iterdir()) # Get Path objects, not strings
        console.print(f"[blue]Copying {len(files)} files from {src.name} to {DEST_DIR}...[/blue]")

        for file_path in tqdm(files, desc=f"Processing {src.name}", unit="file"):
            if file_path.is_file():
                shutil.copy2(file_path, DEST_DIR / file_path.name)

    # 2. Handle Windows PE Files
    console.print(f"[blue]Copying up to {WINDOWS_PE_COUNT} Windows benign files...[/blue]")
    
    count = 0
    # Using rglob to find all .exe files recursively
    for exe_file in tqdm(WINDOWS_PATH.rglob('*.exe'), desc="Scanning Windows"):
        if count >= WINDOWS_PE_COUNT:
            break
        
        try:
            shutil.copy2(exe_file, DEST_DIR / exe_file.name)
            count += 1
        except (PermissionError, OSError):
            continue # Skip files we can't access

    console.print(Panel("[bold green]Success![/bold green] All contents moved to data/raw.", border_style="green"))

if __name__ == "__main__":
    try:
        run_task()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user.[/bold red]")