"""
CyberTool Report Generator Module
"""
import json
import csv
from datetime import datetime
from pathlib import Path
from config import REPORTS_DIR
from core.logger import logger


class ReportGenerator:
    """Generate reports in various formats"""

    def __init__(self):
        self.report_data = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate(self, data, report_type="analysis", formats=None):
        """Generate report in specified formats"""
        if formats is None:
            formats = ["txt"]

        self.report_data = {
            "report_type": report_type,
            "timestamp": datetime.now().isoformat(),
            "tool": "CyberTool v2.0",
            "data": data,
        }

        results = {}
        for fmt in formats:
            if fmt == "txt":
                results["txt"] = self._generate_txt()
            elif fmt == "json":
                results["json"] = self._generate_json()
            elif fmt == "csv":
                results["csv"] = self._generate_csv()
            elif fmt == "html":
                results["html"] = self._generate_html()

        logger.info("ReportGenerator", f"Generated report in formats: {formats}")
        return results

    def _generate_txt(self):
        """Generate TXT report"""
        filename = f"report_{self.timestamp}.txt"
        filepath = REPORTS_DIR / filename

        lines = []
        lines.append("=" * 60)
        lines.append(f" CyberTool v1.0 - Report")
        lines.append(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f" Type: {self.report_data['report_type']}")
        lines.append("=" * 60)
        lines.append("")

        self._dict_to_lines(self.report_data["data"], lines, indent=0)

        filepath.write_text("\n".join(lines), encoding="utf-8")
        return str(filepath)

    def _dict_to_lines(self, data, lines, indent=0):
        """Convert dict to formatted lines"""
        prefix = "  " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                key_str = key.replace("_", " ").title()
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{key_str}:")
                    self._dict_to_lines(value, lines, indent + 1)
                else:
                    lines.append(f"{prefix}{key_str}: {value}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._dict_to_lines(item, lines, indent)
                else:
                    lines.append(f"{prefix}- {item}")

    def _generate_json(self):
        """Generate JSON report"""
        filename = f"report_{self.timestamp}.json"
        filepath = REPORTS_DIR / filename
        filepath.write_text(json.dumps(self.report_data, indent=2, default=str), encoding="utf-8")
        return str(filepath)

    def _generate_csv(self):
        """Generate CSV report"""
        filename = f"report_{self.timestamp}.csv"
        filepath = REPORTS_DIR / filename

        data = self.report_data["data"]
        if isinstance(data, dict):
            # Flatten dict for CSV
            flat_data = self._flatten_dict(data)
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Key", "Value"])
                for key, value in flat_data:
                    writer.writerow([key, value])
        elif isinstance(data, list) and data:
            # List of dicts
            if isinstance(data[0], dict):
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)

        return str(filepath)

    def _flatten_dict(self, d, parent_key=""):
        """Flatten nested dict for CSV"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key))
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v, default=str)))
            else:
                items.append((new_key, str(v)))
        return items

    def _generate_html(self):
        """Generate HTML report"""
        filename = f"report_{self.timestamp}.html"
        filepath = REPORTS_DIR / filename

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberTool Report - {self.report_data['report_type']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1f2937, #374151); padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ color: #58a6ff; font-size: 28px; }}
        .header p {{ color: #8b949e; margin-top: 5px; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 15px; }}
        .section h2 {{ color: #58a6ff; font-size: 18px; margin-bottom: 15px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
        .field {{ display: flex; padding: 8px 0; border-bottom: 1px solid #21262d; }}
        .field:last-child {{ border-bottom: none; }}
        .field-label {{ color: #8b949e; min-width: 200px; font-weight: 500; }}
        .field-value {{ color: #c9d1d9; word-break: break-all; }}
        .risk-low {{ color: #3fb950; }}
        .risk-medium {{ color: #d29922; }}
        .risk-high {{ color: #f85149; }}
        .risk-critical {{ color: #ff0000; font-weight: bold; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; }}
        .badge-danger {{ background: #f85149; color: #fff; }}
        .badge-warning {{ background: #d29922; color: #fff; }}
        .badge-success {{ background: #3fb950; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }}
        th {{ color: #8b949e; font-weight: 500; }}
        tr:hover {{ background: #1c2128; }}
        .footer {{ text-align: center; color: #8b949e; padding: 20px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 CyberTool Report</h1>
            <p>Type: {self.report_data['report_type']} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
"""

        html += self._dict_to_html(self.report_data["data"])

        html += """
        <div class="footer">
            <p>Generated by CyberTool v1.0</p>
        </div>
    </div>
</body>
</html>"""

        filepath.write_text(html, encoding="utf-8")
        return str(filepath)

    def _dict_to_html(self, data, depth=0):
        """Convert dict to HTML sections"""
        html = ""
        if isinstance(data, dict):
            for key, value in data.items():
                key_str = key.replace("_", " ").title()
                if isinstance(value, dict):
                    html += f'<div class="section"><h2>{key_str}</h2>'
                    html += self._dict_to_html(value, depth + 1)
                    html += '</div>'
                elif isinstance(value, list):
                    html += f'<div class="section"><h2>{key_str}</h2>'
                    if value and isinstance(value[0], dict):
                        html += '<table><tr>'
                        for k in value[0].keys():
                            html += f'<th>{k.replace("_", " ").title()}</th>'
                        html += '</tr>'
                        for item in value:
                            html += '<tr>'
                            for k in value[0].keys():
                                v = item.get(k, "")
                                html += f'<td>{v}</td>'
                            html += '</tr>'
                        html += '</table>'
                    else:
                        for item in value:
                            html += f'<div class="field"><span class="field-value">{item}</span></div>'
                    html += '</div>'
                else:
                    risk_class = ""
                    if "risk" in key.lower() or "score" in key.lower():
                        if isinstance(value, str):
                            risk_class = f"risk-{value.lower()}"
                    html += f'<div class="field"><span class="field-label">{key_str}</span><span class="field-value {risk_class}">{value}</span></div>'
        return html