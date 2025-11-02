import csv
from pathlib import Path

INPUT_CSV = Path('output/networks.csv')
OUTPUT_HTML = Path('output/networks_report.html')

if not INPUT_CSV.exists():
    print(f"Warning: {INPUT_CSV} does not exist. Please make sure the Wi-Fi analyzer has generated the CSV first.")
    print("Skipping HTML report generation.")
    exit(0)

# Read CSV data
rows = []
with INPUT_CSV.open(encoding='utf-8') as f:
    reader = csv.DictReader(f)
    headers = reader.fieldnames
    for row in reader:
        rows.append(row)

# Start HTML
html = ['<html><head><title>Wi-Fi Security Report</title>']
html.append('<style>')
html.append('table {border-collapse: collapse; width: 100%;}')
html.append('th, td {border: 1px solid #ccc; padding: 8px; text-align: left;}')
html.append('.critical {background-color: #f28c8c;}')
html.append('.warning {background-color: #f2e28c;}')
html.append('.safe {background-color: #8cf29c;}')
html.append('</style></head><body>')
html.append('<h2>Wi-Fi Security Report</h2>')
html.append('<table>')
html.append('<tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr>')

# Populate rows with color coding
for row in rows:
    enc = row['Encryption'].upper() if 'Encryption' in row else ''
    if 'OPEN' in enc or 'WEP' in enc:
        css_class = 'critical'
    elif 'UNKNOWN' in enc or 'WPA' not in enc:
        css_class = 'warning'
    else:
        css_class = 'safe'
    html.append('<tr>' + ''.join(f'<td class="{css_class}">{row.get(h, '')}</td>' for h in headers) + '</tr>')

html.append('</table></body></html>')

OUTPUT_HTML.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_HTML.open('w', encoding='utf-8') as f:
    f.write('\n'.join(html))

print(f"[+] Report generated: {OUTPUT_HTML}")
