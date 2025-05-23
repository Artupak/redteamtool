from pathlib import Path
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import markdown
from typing import Dict, Any, List, Optional
import logging

class ReportGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.template_dir = Path("reports/templates")
        self.results_dir = Path("results")
        self.output_dir = Path("reports/output")
        
        # Create necessary directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )

    def generate(self, report_name: str, format: str = 'html') -> bool:
        """
        Generate a report from module results.
        
        Args:
            report_name: Name of the report
            format: Output format ('html' or 'pdf')
            
        Returns:
            bool: True if report generation was successful
        """
        try:
            # Load results
            results = self._load_results()
            if not results:
                self.logger.error("No results found to generate report")
                return False

            # Generate report content
            html_content = self._generate_html(results)
            
            # Save report
            if format == 'html':
                return self._save_html(html_content, report_name)
            elif format == 'pdf':
                return self._save_pdf(html_content, report_name)
            else:
                self.logger.error(f"Unsupported format: {format}")
                return False

        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return False

    def _load_results(self) -> List[Dict[str, Any]]:
        """
        Load all results from the results directory.
        """
        results = []
        
        try:
            for result_file in self.results_dir.glob("*.json"):
                with open(result_file, 'r') as f:
                    result = json.load(f)
                    results.append(result)
        except Exception as e:
            self.logger.error(f"Error loading results: {str(e)}")
            
        return results

    def _generate_html(self, results: List[Dict[str, Any]]) -> str:
        """
        Generate HTML report content.
        """
        template = self.env.get_template('report.html')
        
        # Prepare data for the template
        report_data = {
            'title': 'Red Team Operation Report',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'modules': results,
            'summary': self._generate_summary(results)
        }
        
        return template.render(**report_data)

    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of all module results.
        """
        summary = {
            'total_modules': len(results),
            'successful_modules': 0,
            'failed_modules': 0,
            'start_time': None,
            'end_time': None
        }
        
        for result in results:
            # Count successes and failures
            if 'error' not in result:
                summary['successful_modules'] += 1
            else:
                summary['failed_modules'] += 1
                
            # Track timeline
            start = datetime.fromisoformat(result.get('start_time', '9999-12-31T23:59:59'))
            end = datetime.fromisoformat(result.get('end_time', '1970-01-01T00:00:00'))
            
            if not summary['start_time'] or start < summary['start_time']:
                summary['start_time'] = start
            if not summary['end_time'] or end > summary['end_time']:
                summary['end_time'] = end
        
        return summary

    def _save_html(self, content: str, report_name: str) -> bool:
        """
        Save report as HTML file.
        """
        try:
            output_file = self.output_dir / f"{report_name}.html"
            with open(output_file, 'w') as f:
                f.write(content)
            self.logger.info(f"HTML report saved to: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving HTML report: {str(e)}")
            return False

    def _save_pdf(self, content: str, report_name: str) -> bool:
        """
        Save report as PDF file.
        """
        try:
            output_file = self.output_dir / f"{report_name}.pdf"
            HTML(string=content).write_pdf(str(output_file))
            self.logger.info(f"PDF report saved to: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving PDF report: {str(e)}")
            return False 