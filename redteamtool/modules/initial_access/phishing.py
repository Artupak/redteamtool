from core.base_module import BaseModule
from typing import Dict, Any, List
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import yaml
from pathlib import Path
from datetime import datetime
import jinja2
import csv
import logging

class PhishingModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "PhishingSimulation"
        self.description = "Simulates phishing attacks for security awareness testing"
        self.author = "ARTUPAK"
        self.references = [
            "https://attack.mitre.org/techniques/T1566/001/",
            "https://attack.mitre.org/techniques/T1566/002/"
        ]
        
        # Define module options
        self.options = {
            'smtp_server': {
                'value': None,
                'required': True,
                'description': 'SMTP server for sending emails'
            },
            'smtp_port': {
                'value': 587,
                'required': False,
                'description': 'SMTP port'
            },
            'smtp_username': {
                'value': None,
                'required': True,
                'description': 'SMTP username'
            },
            'smtp_password': {
                'value': None,
                'required': True,
                'description': 'SMTP password'
            },
            'from_email': {
                'value': None,
                'required': True,
                'description': 'Sender email address'
            },
            'targets_file': {
                'value': None,
                'required': True,
                'description': 'CSV file containing target email addresses'
            },
            'template_file': {
                'value': None,
                'required': True,
                'description': 'Email template file (HTML)'
            },
            'attachment_file': {
                'value': None,
                'required': False,
                'description': 'Optional attachment file'
            }
        }
        
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def run(self, target: str, **kwargs) -> bool:
        """
        Execute the phishing simulation module.
        """
        try:
            # Update options from kwargs
            for key, value in kwargs.items():
                if key in self.options:
                    self.set_option(key, value)

            # Validate options
            if not self.validate_options():
                return False

            # Start module execution
            self.pre_run()

            # Load targets
            targets = self._load_targets()
            if not targets:
                self.logger.error("No valid targets found")
                return False

            # Load email template
            template = self._load_template()
            if not template:
                self.logger.error("Failed to load email template")
                return False

            # Send phishing emails
            success_count = 0
            fail_count = 0
            
            for target in targets:
                try:
                    if self._send_phishing_email(target, template):
                        success_count += 1
                    else:
                        fail_count += 1
                except Exception as e:
                    self.logger.error(f"Error sending email to {target['email']}: {str(e)}")
                    fail_count += 1

            # Store results
            self.results = {
                'total_targets': len(targets),
                'successful_sends': success_count,
                'failed_sends': fail_count,
                'timestamp': datetime.now().isoformat()
            }

            # Save results
            self.save_results()
            
            # Cleanup
            self.post_run()
            
            return True

        except Exception as e:
            self.add_result('error', str(e))
            return False

    def _load_targets(self) -> List[Dict[str, str]]:
        """
        Load target email addresses and metadata from CSV file.
        """
        targets = []
        targets_file = self.get_option('targets_file')
        
        try:
            with open(targets_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'email' in row:
                        targets.append(row)
                    else:
                        self.logger.warning("CSV row missing email field")
        except Exception as e:
            self.logger.error(f"Error loading targets file: {str(e)}")
            return []
            
        return targets

    def _load_template(self) -> jinja2.Template:
        """
        Load and parse email template.
        """
        template_file = self.get_option('template_file')
        
        try:
            with open(template_file, 'r') as f:
                template_str = f.read()
                
            return jinja2.Template(template_str)
        except Exception as e:
            self.logger.error(f"Error loading template file: {str(e)}")
            return None

    def _send_phishing_email(self, target: Dict[str, str], template: jinja2.Template) -> bool:
        """
        Send phishing email to a single target.
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "Important Security Update"  # Could be customized per template
            msg['From'] = self.get_option('from_email')
            msg['To'] = target['email']

            # Render HTML content
            html_content = template.render(**target)
            msg.attach(MIMEText(html_content, 'html'))

            # Add attachment if specified
            attachment_file = self.get_option('attachment_file')
            if attachment_file:
                with open(attachment_file, 'rb') as f:
                    attachment = MIMEApplication(f.read())
                    attachment.add_header(
                        'Content-Disposition', 
                        'attachment', 
                        filename=Path(attachment_file).name
                    )
                    msg.attach(attachment)

            # Connect to SMTP server
            smtp_server = self.get_option('smtp_server')
            smtp_port = self.get_option('smtp_port')
            smtp_username = self.get_option('smtp_username')
            smtp_password = self.get_option('smtp_password')

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)

            self.logger.info(f"Successfully sent phishing email to {target['email']}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send phishing email to {target['email']}: {str(e)}")
            return False 