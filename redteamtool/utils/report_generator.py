import os
import json
import datetime
from jinja2 import Template
from weasyprint import HTML
from typing import Dict, List, Any

class ReportGenerator:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'reports')
        self.results_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'results')
        
        # Ensure directories exist
        os.makedirs(self.template_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)

    def _load_template(self) -> str:
        """Load the HTML template file."""
        template_path = os.path.join(self.template_dir, 'report_template.html')
        with open(template_path, 'r') as f:
            return f.read()

    def generate_report(self, data: Dict[str, Any], output_format: str = 'both') -> str:
        """
        Generate a report using the provided data.
        
        Args:
            data: Dictionary containing all the report data
            output_format: 'html', 'pdf', or 'both'
            
        Returns:
            Path to the generated report file(s)
        """
        # Add timestamp if not present
        if 'timestamp' not in data:
            data['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
        # Generate report ID if not present
        if 'report_id' not in data:
            data['report_id'] = f"RTR-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Load and render template
        template = Template(self._load_template())
        html_content = template.render(**data)

        # Create output directory for this report
        report_dir = os.path.join(self.results_dir, data['report_id'])
        os.makedirs(report_dir, exist_ok=True)

        outputs = []

        # Save HTML version
        if output_format in ['html', 'both']:
            html_path = os.path.join(report_dir, 'report.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            outputs.append(html_path)

        # Generate PDF version
        if output_format in ['pdf', 'both']:
            pdf_path = os.path.join(report_dir, 'report.pdf')
            try:
                HTML(string=html_content).write_pdf(pdf_path)
                outputs.append(pdf_path)
            except Exception as e:
                print(f"Uyarı: PDF oluşturma başarısız oldu: {str(e)}")

        return outputs[0] if len(outputs) == 1 else outputs

    def generate_finding_entry(self, title: str, severity: str, description: str,
                             impact: str, recommendation: str) -> Dict[str, str]:
        """Helper method to generate a properly formatted finding entry."""
        return {
            'title': title,
            'severity': severity.lower(),
            'description': description,
            'impact': impact,
            'recommendation': recommendation
        }

    def format_network_discovery_result(self, host: str, ports: List[Dict],
                                      services: List[str], vulns: List[str]) -> str:
        """Helper method to format network discovery results."""
        return f"""
        <tr>
            <td>{host}</td>
            <td>{', '.join(f"{p['port']}/{p['protocol']}" for p in ports)}</td>
            <td>{', '.join(services)}</td>
            <td>{', '.join(vulns)}</td>
        </tr>
        """ 