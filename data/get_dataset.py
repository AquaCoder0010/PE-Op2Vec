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
BENIGN_DEST_DIR = CWD / "data" / "train" / "benign"
MALWARE_DEST_DIR = CWD / "data" / "train" / "malware"

# Create destination if it doesn't exist
BENIGN_DEST_DIR.mkdir(parents=True, exist_ok=True)
MALWARE_DEST_DIR.mkdir(parents=True, exist_ok=True)

BENIGN_SRC = BASE_DIR / "files" / "benign"
MALWARE_SRC = BASE_DIR / "files" / "malware"

console = Console()

def run_task():
    console.print(Panel.fit("[bold blue]Processing DikeDataset[/bold blue]", border_style="cyan"))

    # Clone repository if needed
    if not BASE_DIR.exists():
        console.print(f"[yellow]Cloning repository: {REPO_URL}...[/yellow]")
        exit_code = os.system(f"git clone {REPO_URL}")
        
        if exit_code != 0:
            console.print("[bold red]Error: Failed to clone repository.[/bold red]")
            return
    else:
        console.print("[green]Repository already exists. Skipping clone.[/green]")

    # Copy DikeDataset files
    sources = [BENIGN_SRC, MALWARE_SRC]
    
    for src in sources:
        if not src.exists():
            console.print(f"[bold red]Warning: Source path {src} not found![/bold red]")
            continue
        
        copy_dist = BENIGN_DEST_DIR if src == BENIGN_SRC else MALWARE_DEST_DIR

        files = list(src.iterdir())
        console.print(f"[blue]Copying {len(files)} files from {src.name} to {copy_dist}...[/blue]")

        for file_path in tqdm(files, desc=f"Processing {src.name}", unit="file"):
            if file_path.is_file():
                shutil.copy2(file_path, copy_dist / file_path.name)

    # Copy Windows benign PE files
    console.print(f"[blue]Copying up to {WINDOWS_PE_COUNT} Windows benign files...[/blue]")

    if not WINDOWS_PATH.exists():
        console.print(f"[bold red]Windows path {WINDOWS_PATH} does not exist. Skipping.[/bold red]")
        return

    count = 0
    # Use os.walk with error handling to avoid stopping on inaccessible directories
    pbar = tqdm(total=WINDOWS_PE_COUNT, desc="Copying Windows EXEs", unit="file")

    def onerror(error):
        # Called when os.walk cannot list a directory
        console.print(f"[yellow]Skipping directory due to error: {error}[/yellow]")

    try:
        for root, dirs, files in os.walk(WINDOWS_PATH, onerror=onerror):
            for file in files:
                if file.lower().endswith('.exe'):
                    src_path = Path(root) / file
                    dest_path = BENIGN_DEST_DIR / src_path.name
                    # If file already exists, rename to avoid overwrite
                    if dest_path.exists():
                        stem = dest_path.stem
                        suffix = dest_path.suffix
                        counter = 1
                        while dest_path.exists():
                            new_name = f"{stem}_{counter}{suffix}"
                            dest_path = BENIGN_DEST_DIR / new_name
                            counter += 1
                    try:
                        shutil.copy2(src_path, dest_path)
                        count += 1
                        pbar.update(1)
                        if count >= WINDOWS_PE_COUNT:
                            break
                    except (PermissionError, OSError) as e:
                        console.print(f"[yellow]Skipping {src_path}: {e}[/yellow]")
                        continue
            if count >= WINDOWS_PE_COUNT:
                break
    except Exception as e:
        console.print(f"[red]Unexpected error during traversal: {e}[/red]")
    finally:
        pbar.close()

    console.print(Panel("[bold green]Success![/bold green] All contents moved to data/train (benign and malware).", border_style="green"))

if __name__ == "__main__":
    try:
        run_task()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user.[/bold red]")