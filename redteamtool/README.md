# RedTeamOps

A comprehensive, modular Red Team Operations framework for security testing and assessment.

## Features

- **Modular Architecture**: Easily extensible with new attack modules
- **Comprehensive Modules**:
  - Network Discovery
  - Phishing Simulation
  - Linux Privilege Escalation
  - Windows Lateral Movement
- **Advanced Reporting**: Generate detailed HTML/PDF reports
- **Configurable Options**: Extensive configuration for each module
- **Security-First**: Built-in security measures and cleanup procedures
## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py [module] [options]
```

### Available Modules

1. Network Discovery
   ```bash
   python main.py network-discovery --target 192.168.1.0/24
   ```

2. Phishing Simulation
   ```bash
   python main.py phishing --template corporate --targets targets.txt
   ```

3. Linux Privilege Escalation
   ```bash
   python main.py linux-privesc --target ssh://user@host
   ```

4. Windows Lateral Movement
   ```bash
   python main.py lateral-movement --method psexec --target-list hosts.txt
   ```

## Configuration

Each module supports extensive configuration through YAML files in the `config/` directory.

## Security Notice

This tool is intended for authorized security testing only. Ensure you have proper permissions before using any module.

## License

MIT License - See LICENSE file for details.
{
    # Aracı yükle
pip install -r requirements.txt

# Mevcut modülleri listele
python main.py modules

# Ağ keşfini başlat
python main.py network-discovery --target 192.168.1.0/24

# Linux yetki yükseltme testi
python main.py linux-privesc --target ssh://user@host

# Windows yanal hareket başlat
python main.py lateral-movement --method psexec --target-list hosts.txt

}