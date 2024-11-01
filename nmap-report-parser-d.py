import xml.etree.ElementTree as ET
import pandas as pd
import glob
import os
from datetime import datetime

class NmapReportParser:
    def __init__(self):
        self.results = []
        self.files_processed = 0
        self.hosts_found = 0
 
    def parse_gnmap_report(self, file_path):
        """Parse a single GNMAP report."""
        print(f"\nParsing GNMAP file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                host_count = 0
                for line in f:
                    if 'Host: ' not in line:
                        continue
                    
                    host_count += 1
                    self.hosts_found += 1
                        
                    parts = line.split('\t')
                    host_info = parts[0].split(' ')
                    ip = host_info[1]
                    print(f"Processing host: {ip}")
                    
                    # Extract hostname if exists
                    hostname = ''
                    if '(' in line and ')' in line:
                        hostname = line[line.find('(')+1:line.find(')')]
                    
                    # Extract status
                    status = 'unknown'
                    if 'Status: ' in line:
                        status = line[line.find('Status: ')+8:].split()[0]
                    
                    if 'Ports: ' not in line:
                        # Add host even if no ports found
                        self._add_result(
                            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            ip,
                            hostname,
                            status,
                            None,
                            {}
                        )
                        continue
                    
                    ports_info = line[line.find('Ports: ')+7:].strip()
                    port_count = 0
                    for port_info in ports_info.split(','):
                        port_data = port_info.strip().split('/')
                        if len(port_data) < 7:
                            continue
                            
                        port_count += 1
                        
                        port_dict = {
                            'port': port_data[0],
                            'state': port_data[1],
                            'protocol': port_data[2],
                            'reason': '',  # Not available in GNMAP format
                            'service': port_data[4],
                            'product': port_data[6],
                            'version': port_data[7] if len(port_data) > 7 else '',
                            'extra_info': ' '.join(port_data[8:]) if len(port_data) > 8 else ''
                        }
                        
                        self._add_result(
                            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            ip,
                            hostname,
                            status,
                            port_dict,
                            {}
                        )
                    
                    print(f"Found {port_count} ports for host {ip}")
                
                print(f"Found {host_count} hosts in file")
                self.files_processed += 1
                
        except Exception as e:
            print(f"Error processing GNMAP file {file_path}: {str(e)}")   
     
    def parse_xml_report(self, file_path):
        """Parse a single XML Nmap report."""
        print(f"\nParsing XML file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            if root.tag != 'nmaprun':
                print(f"Warning: {file_path} might not be an Nmap XML file (root tag: {root.tag})")
                return
            
            scan_time = root.attrib.get('startstr', 'Unknown')
            print(f"Scan time: {scan_time}")
            
            hosts = root.findall('.//host')
            print(f"Found {len(hosts)} hosts in file")
            
            for host in hosts:
                self.hosts_found += 1
                
                # Get host state
                status = host.find('status').attrib
                host_state = f"{status['state']} ({status.get('reason', 'unknown reason')})"
                
                # Get IP
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is None:
                    print(f"Warning: No IPv4 address found for host in {file_path}")
                    continue
                    
                ip = ip_elem.attrib['addr']
                print(f"Processing host: {ip}")
                
                # Get hostname
                hostname_elem = host.find('.//hostname')
                hostname = hostname_elem.attrib['name'] if hostname_elem is not None else ''
                
                # Get OS detection information
                os_info = self._parse_os_info(host)
                
                # Get ports
                ports = host.findall('.//port')
                print(f"Found {len(ports)} ports for host {ip}")
                
                if not ports:
                    # Add host even if no open ports
                    self._add_result(scan_time, ip, hostname, host_state, None, os_info)
                
                for port in ports:
                    port_data = self._parse_port_info(port)
                    self._add_result(scan_time, ip, hostname, host_state, port_data, os_info)
            
            self.files_processed += 1
            
        except ET.ParseError as e:
            print(f"XML Parse Error in {file_path}: {str(e)}")
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")

    def generate_html_report(self, output_file):
        """Generate an HTML report from the parsed results."""
        print(f"\nGenerating HTML report: {output_file}")
        df = pd.DataFrame(self.results)
        
        # Create HTML template with Bootstrap - using triple quotes properly
        html_template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Nmap Scan Results</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.24/css/dataTables.bootstrap5.css"/>
            <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
            <script type="text/javascript" src="https://cdn.datatables.net/1.10.24/js/jquery.dataTables.min.js"></script>
            <script type="text/javascript" src="https://cdn.datatables.net/1.10.24/js/dataTables.bootstrap5.min.js"></script>
            <style>
                .closed-port {{ color: #dc3545; }}
                .filtered-port {{ color: #ffc107; }}
                .open-port {{ color: #198754; }}
            </style>
        </head>
        <body>
            <div class="container-fluid mt-5">
                <h2>Nmap Scan Results</h2>
                <p>Generated on: {datetime}</p>
                <p>Total hosts scanned: {total_hosts}</p>
                <p>Total files processed: {total_files}</p>
                {table}
            </div>
            <script>
                $(document).ready(function() {{
                    $('#results').DataTable({{
                        pageLength: 25,
                        order: [[0, 'asc']],
                        createdRow: function(row, data, dataIndex) {{
                            if (data[6] === 'closed') {{
                                $(row).find('td:eq(6)').addClass('closed-port');
                            }} else if (data[6] === 'filtered') {{
                                $(row).find('td:eq(6)').addClass('filtered-port');
                            }} else if (data[6] === 'open') {{
                                $(row).find('td:eq(6)').addClass('open-port');
                            }}
                        }}
                    }});
                }});
            </script>
        </body>
        </html>
        '''
        
        # Convert DataFrame to HTML and insert into template
        html_content = html_template.format(
            datetime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_hosts=self.hosts_found,
            total_files=self.files_processed,
            table=df.to_html(classes='table table-striped table-bordered', table_id='results', index=False)
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report generated: {output_file}")

    def generate_excel_report(self, output_file):
        """Generate an Excel report from the parsed results."""
        print(f"\nGenerating Excel report: {output_file}")
        df = pd.DataFrame(self.results)
        
        # Create Excel writer object
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Scan Results', index=False)
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Scan Results']
            for idx, col in enumerate(df.columns):
                max_length = max(
                    df[col].astype(str).apply(len).max(),
                    len(col)
                ) + 2
                worksheet.column_dimensions[chr(65 + idx)].width = max_length
        
        print(f"Excel report generated: {output_file}")


    def _add_result(self, scan_time, ip, hostname, host_state, port_data, os_info):
        """Helper method to add a result to the results list"""
        if port_data is None:
            port_data = {
                'port': '',
                'protocol': '',
                'state': '',
                'reason': '',
                'service': '',
                'product': '',
                'version': '',
                'extra_info': ''
            }
            
        self.results.append({
            'scan_time': scan_time,
            'ip_address': ip,
            'hostname': hostname,
            'host_state': host_state,
            'port': port_data['port'],
            'protocol': port_data['protocol'],
            'port_state': port_data['state'],
            'port_reason': port_data['reason'],
            'service': port_data['service'],
            'product': port_data['product'],
            'version': port_data['version'],
            'extra_info': port_data['extra_info'],
            'os_name': os_info.get('os_name', ''),
            'os_accuracy': os_info.get('os_accuracy', ''),
            'os_family': os_info.get('os_family', ''),
            'os_details': os_info.get('os_details', '')
        })

    def parse_directory(self, directory_path, recursive=True):
        """Parse all Nmap reports in a directory and its subdirectories."""
        print(f"\nStarting scan of directory: {directory_path}")
        print(f"Recursive mode: {recursive}")
        
        if not os.path.exists(directory_path):
            print(f"Error: Directory {directory_path} does not exist!")
            return
            
        if recursive:
            # Walk through directory and all subdirectories
            for root, dirs, files in os.walk(directory_path):
                print(f"\nScanning directory: {root}")
                print(f"Found subdirectories: {dirs}")
                
                # Parse XML files in current directory
                xml_files = [f for f in files if f.lower().endswith('.xml')]
                print(f"Found XML files: {xml_files}")
                
                for xml_file in xml_files:
                    file_path = os.path.join(root, xml_file)
                    self.parse_xml_report(file_path)
                
                # Parse GNMAP files in current directory
                gnmap_files = [f for f in files if f.lower().endswith('.gnmap')]
                print(f"Found GNMAP files: {gnmap_files}")
                
                for gnmap_file in gnmap_files:
                    file_path = os.path.join(root, gnmap_file)
                    self.parse_gnmap_report(file_path)
        else:
            # Non-recursive search
            xml_files = glob.glob(os.path.join(directory_path, '*.xml'))
            print(f"Found XML files: {xml_files}")
            
            for xml_file in xml_files:
                self.parse_xml_report(xml_file)
            
            gnmap_files = glob.glob(os.path.join(directory_path, '*.gnmap'))
            print(f"Found GNMAP files: {gnmap_files}")
            
            for gnmap_file in gnmap_files:
                self.parse_gnmap_report(gnmap_file)
        
        print(f"\nProcessing complete!")
        print(f"Files processed: {self.files_processed}")
        print(f"Total hosts found: {self.hosts_found}")
        print(f"Total results entries: {len(self.results)}")

    # [Other methods remain the same]

if __name__ == "__main__":
    import argparse
    
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Parse Nmap scan results recursively from a directory.')
    parser.add_argument('directory', help='Directory containing nmap scan results')
    parser.add_argument('--no-recursive', action='store_true', help='Do not search subdirectories')
    parser.add_argument('--html', default='nmap_report.html', help='Output HTML file name (default: nmap_report.html)')
    parser.add_argument('--excel', default='nmap_report.xlsx', help='Output Excel file name (default: nmap_report.xlsx)')
    
    args = parser.parse_args()
    
    # Create parser and process files
    nmap_parser = NmapReportParser()
    
    # Process files
    nmap_parser.parse_directory(args.directory, recursive=not args.no_recursive)
    
    # Check if we have any results before generating reports
    if not nmap_parser.results:
        print("\nWarning: No results found! Reports will be empty.")
        print("Please check:")
        print("1. Are there .xml or .gnmap files in the specified directory?")
        print("2. Are the files valid Nmap output files?")
        print("3. Did the original Nmap scans complete successfully?")
    else:
        # Generate reports
        print(f"\nGenerating HTML report: {args.html}")
        nmap_parser.generate_html_report(args.html)
        print(f"Generating Excel report: {args.excel}")
        nmap_parser.generate_excel_report(args.excel)
        print("Done!")

