#!/usr/bin/env python3

import click
import yaml
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from typing import Dict, Any, Optional

# Import modules
from modules.network_discovery import NetworkDiscoveryModule
from modules.phishing import PhishingModule
from modules.linux_privesc import LinuxPrivescModule
from modules.lateral_movement import LateralMovementModule

console = Console()

MODULES = {
    'network-discovery': NetworkDiscoveryModule,
    'phishing': PhishingModule,
    'linux-privesc': LinuxPrivescModule,
    'lateral-movement': LateralMovementModule
}

def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        console.print(f"[red]Error loading config file: {str(e)}[/red]")
        sys.exit(1)

def list_modules() -> None:
    """Display available modules and their descriptions."""
    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="green")
    
    for name, module_class in MODULES.items():
        module = module_class(name, "")  # Temporary instance for description
        table.add_row(name, module.description)
    
    console.print(table)

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """RedTeamOps - Advanced Red Team Operations Framework"""
    pass

@cli.command()
def modules():
    """List available modules"""
    list_modules()

@cli.command()
@click.argument('module_name')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--target', '-t', help='Target system or network')
@click.option('--output', '-o', help='Output directory for results')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def run(module_name: str, config: Optional[str], target: Optional[str], output: Optional[str], verbose: bool):
    """Run a specific module"""
    if module_name not in MODULES:
        console.print(f"[red]Error: Module '{module_name}' not found[/red]")
        sys.exit(1)

    # Create module instance
    module_class = MODULES[module_name]
    module = module_class(module_name, "")

    # Load configuration if provided
    if config:
        module.load_config(config)

    # Set command line options
    if target:
        module.set_option('target', target)
    if output:
        module.set_option('output_dir', output)
    if verbose:
        module.set_option('verbose', True)

    # Validate and run module
    try:
        if not module.validate_options():
            console.print("[red]Error: Missing required options[/red]")
            sys.exit(1)

        with module:
            success = module.run()
            if success:
                module.save_results()
                console.print("[green]Module execution completed successfully[/green]")
            else:
                console.print("[red]Module execution failed[/red]")
                sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error during module execution: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.argument('module_name')
def info(module_name: str):
    """Display detailed information about a module"""
    if module_name not in MODULES:
        console.print(f"[red]Error: Module '{module_name}' not found[/red]")
        sys.exit(1)

    module_class = MODULES[module_name]
    module = module_class(module_name, "")

    table = Table(title=f"Module Information: {module_name}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Name", module.name)
    table.add_row("Description", module.description)
    table.add_row("Author", module.author)
    table.add_row("Required Options", "\n".join(module.get_required_options()))

    console.print(table)

if __name__ == '__main__':
    # Create necessary directories
    Path("logs").mkdir(exist_ok=True)
    Path("results").mkdir(exist_ok=True)
    Path("config").mkdir(exist_ok=True)

    cli()
