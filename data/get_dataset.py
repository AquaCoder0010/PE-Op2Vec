import os
import shutil
from pathlib import Path
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel

# --- Configuration ---

REPO_URL = "https://github.com/iosifache/DikeDataset.git"
REPO_NAME = "DikeDataset"

# Define source and destination
BASE_DIR = Path("data" + "/"  + REPO_NAME)
BENIGN_SRC = BASE_DIR / "file" / "benign"
MALWARE_SRC = BASE_DIR / "file" / "malware"
DEST_DIR = Path("data/raw")

console = Console()

def run_task():
    console.print(Panel.fit("[bold blue] Downloading DikeDataset >3[/bold blue]", border_style="cyan"))

    if not BASE_DIR.exists():
        console.print(f"[yellow]Cloning repository: {REPO_URL}...[/yellow]")
        exit_code = os.system(f"git clone {REPO_URL}")
        
        if exit_code != 0:
            console.print("[bold red]Error: Failed to clone repository.[/bold red]")
            return
    else:
        console.print("[green]Repository already exists. Skipping clone.[/green]")

    DEST_DIR.mkdir(parents=True, exist_ok=True)

    files_to_copy = []
    for src in [BENIGN_SRC, MALWARE_SRC]:
        if src.exists():
            files_to_copy.extend(list(src.iterdir()))
        else:
            console.print(f"[bold red]Warning: Source path {src} not found![/bold red]")

    if not files_to_copy:
        console.print("[red]No files found to copy.[/red]")
        return

    console.print(f"[blue]Copying {len(files_to_copy)} files to {DEST_DIR}...[/blue]")
    
    for file_path in tqdm(files_to_copy, desc="Processing Files", unit="file"):
        if file_path.is_file():
            shutil.copy2(file_path, DEST_DIR / file_path.name)

    console.print(Panel("[bold green]Success![/bold green] All contents moved to data/raw.", border_style="green"))

if __name__ == "__main__":
    try:
        run_task()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user.[/bold red]")