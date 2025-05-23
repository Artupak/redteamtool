from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import yaml
import logging
from datetime import datetime
from pathlib import Path
import json
from rich.console import Console

console = Console()

class BaseModule(ABC):
    """Base class for all RedTeamOps attack modules."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.logger = self._setup_logging()
        self.author: str = "Unknown"
        self.references: list = []
        self.options: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def _setup_logging(self) -> logging.Logger:
        """Set up module-specific logging."""
        logger = logging.getLogger(self.name)
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Create file handler
        fh = logging.FileHandler(f"logs/{self.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        fh.setLevel(logging.DEBUG)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger

    def load_config(self, config_file: str) -> None:
        """Load module configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                self.options.update(yaml.safe_load(f))
        except Exception as e:
            self.logger.error(f"Failed to load config file {config_file}: {str(e)}")
            raise

    def set_option(self, key: str, value: Any) -> None:
        """Set a module option."""
        self.options[key] = value

    def get_option(self, key: str, default: Any = None) -> Any:
        """Get a module option value."""
        return self.options.get(key, default)

    def validate_options(self) -> bool:
        """Validate that all required options are set."""
        required_options = self.get_required_options()
        for option in required_options:
            if option not in self.options:
                self.logger.error(f"Missing required option: {option}")
                return False
        return True

    @abstractmethod
    def get_required_options(self) -> list:
        """Return list of required options for the module."""
        pass

    @abstractmethod
    def run(self, target: str, **kwargs) -> bool:
        """Execute the module's main functionality."""
        pass

    def pre_run(self) -> bool:
        """Perform pre-run checks and setup."""
        if not self.validate_options():
            return False
        self.start_time = datetime.now()
        self.logger.info(f"Starting {self.name} module execution")
        self.results = {}
        console.print(f"[bold blue]Starting module: {self.name}[/bold blue]")
        console.print(f"[blue]Target: {self.options.get('target', 'Not specified')}[/blue]")
        return True

    def post_run(self, success: bool) -> None:
        """Perform post-run cleanup and logging."""
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time if self.start_time else None
        
        if success:
            self.logger.info(f"Module {self.name} completed successfully")
            console.print(f"[bold blue]Module {self.name} completed[/bold blue]")
        else:
            self.logger.error(f"Module {self.name} failed")
            console.print(f"[red]Module {self.name} failed[/red]")
            
        if duration:
            self.logger.info(f"Execution time: {duration}")
            console.print(f"[blue]Duration: {duration}[/blue]")

    def cleanup(self) -> None:
        """Clean up any resources or artifacts created during execution."""
        pass

    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of the module's execution."""
        return {
            "module_name": self.name,
            "description": self.description,
            "author": self.author,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "options": self.options,
            "results": self.results
        }

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
        if exc_type:
            self.logger.error(f"Exception occurred: {exc_val}")
            return False
        return True

    def save_results(self) -> None:
        """
        Save module execution results to a JSON file.
        """
        if not self.results:
            return

        # Create results directory if it doesn't exist
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)

        # Create a timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = results_dir / f"{self.name}_{timestamp}.json"

        # Add metadata to results
        full_results = {
            "module_name": self.name,
            "description": self.description,
            "author": self.author,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "options": self.options,
            "results": self.results
        }

        # Save to file
        try:
            with open(filename, 'w') as f:
                json.dump(full_results, f, indent=4)
            console.print(f"[green]Results saved to: {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {str(e)}[/red]") 