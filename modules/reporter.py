import json
from datetime import datetime
from typing import Dict, Any

def generate_json_report(results: Dict[str, Any]) -> str:
    """Generates formatted JSON artifact for SIEM/SOAR ingestion."""
    report_data = {
        "report_metadata": {
            "title": "LOSTKEYS Defensive Threat Analysis Report",
            "generator": "LOSTKEYS Threat Detector v1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "threat_actor": "COLDRIVER / Star Blizzard (GTIG 2025)",
            "classification": "DEFENSIVE THREAT INTEL - UNCLASSIFIED"
        },
        "analysis_results": results
    }
    return json.dumps(report_data, indent=2)

def generate_html_report(results: Dict[str, Any]) -> str:
    """Generates a styled standalone HTML investigation report."""
    risk_level = results.get("risk_level", "LOW")
    score = results.get("score", 0)
    sha256 = results.get("sha256", "N/A")
    filename = results.get("filename", "Unknown Sample")
    entropy = results.get("entropy", 0.0)
    signals = results.get("signals", [])
    matched_iocs = results.get("matched_iocs", [])
    mitre_mappings = results.get("mitre_mappings", [])
    decoded_payloads = results.get("decoded_payloads", [])
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Risk badge color selection
    badge_colors = {
        "CRITICAL": "#FF2A4B",
        "HIGH": "#FF8C00",
        "MEDIUM": "#FFD700",
        "LOW": "#00E676"
    }
    badge_color = badge_colors.get(risk_level, "#00E676")

    signals_html = ""
    for sig in signals:
        signals_html += f"""
        <div style="background: rgba(255,255,255,0.03); border-left: 4px solid {badge_color}; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; font-weight: bold;">
                <span style="color: #64FFDA;">[{sig.get('category', 'Signal')}] {sig.get('rule', 'Rule')}</span>
                <span style="color: #FF2A4B;">+{sig.get('points', 0)} pts</span>
            </div>
            <div style="font-size: 0.9em; color: #CCD6F6; margin-top: 4px;">{sig.get('evidence', '')}</div>
        </div>
        """

    iocs_html = ""
    if matched_iocs:
        for ioc in matched_iocs:
            iocs_html += f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #233554; color: #64FFDA;">{ioc.get('type')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #233554; font-family: monospace; color: #FF2A4B;">{ioc.get('value')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #233554; color: #8892B0;">{ioc.get('description')}</td>
            </tr>
            """
    else:
        iocs_html = '<tr><td colspan="3" style="padding: 10px; color: #8892B0;">No historical GTIG IOC matches found in sample.</td></tr>'

    mitre_html = ""
    if mitre_mappings:
        for m in mitre_mappings:
            mitre_html += f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #233554; font-weight: bold; color: #FFD700;">{m.get('id')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #233554; color: #E6F1FF;">{m.get('name')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #233554; color: #64FFDA;">{m.get('tactic', 'Execution')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #233554; color: #8892B0; font-size: 0.9em;">{m.get('description')}</td>
            </tr>
            """
    else:
        mitre_html = '<tr><td colspan="4" style="padding: 10px; color: #8892B0;">No MITRE ATT&CK techniques mapped.</td></tr>'

    decoded_html = ""
    if decoded_payloads:
        for dp in decoded_payloads:
            decoded_html += f"""
            <div style="background: #0A192F; border: 1px solid #233554; padding: 12px; border-radius: 6px; margin-bottom: 10px;">
                <div style="color: #64FFDA; font-size: 0.85em; font-family: monospace;">Encoded snippet: {dp.get('encoded_sample')}</div>
                <pre style="background: #020C1B; color: #00E676; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 0.85em;">{dp.get('decoded_text')}</pre>
            </div>
            """
    else:
        decoded_html = '<p style="color: #8892B0;">No encoded base64 payloads detected.</p>'

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LOSTKEYS Malware Analysis Report - {filename}</title>
    <style>
        body {{
            background-color: #0A192F;
            color: #8892B0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: #112240;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 30px -15px rgba(2,12,27,0.7);
            border: 1px solid #233554;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #233554;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .title {{
            color: #CCD6F6;
            font-size: 24px;
            font-weight: bold;
        }}
        .subtitle {{
            color: #64FFDA;
            font-size: 14px;
            margin-top: 5px;
        }}
        .badge {{
            background-color: {badge_color};
            color: #000;
            font-weight: bold;
            padding: 8px 18px;
            border-radius: 20px;
            font-size: 18px;
            display: inline-block;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: #0A192F;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #233554;
        }}
        .metric-label {{
            font-size: 12px;
            color: #8892B0;
            text-transform: uppercase;
        }}
        .metric-val {{
            font-size: 18px;
            color: #64FFDA;
            font-weight: bold;
            margin-top: 5px;
            word-break: break-all;
        }}
        h2 {{
            color: #CCD6F6;
            font-size: 18px;
            border-bottom: 1px solid #233554;
            padding-bottom: 8px;
            margin-top: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th {{
            background: #0A192F;
            color: #CCD6F6;
            text-align: left;
            padding: 12px;
            border-bottom: 2px solid #233554;
        }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #48566E;
            border-top: 1px solid #233554;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="title">LOSTKEYS Defensive Threat Analysis Report</div>
                <div class="subtitle">COLDRIVER / Star Blizzard (GTIG 2025) ClickFix Case Study</div>
            </div>
            <div>
                <span class="badge">{risk_level} ({score} PTS)</span>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Analyzed File / Sample</div>
                <div class="metric-val">{filename}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">SHA-256 Checksum</div>
                <div class="metric-val" style="font-size: 13px;">{sha256}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Shannon Entropy</div>
                <div class="metric-val">{entropy} / 8.0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Analysis Timestamp</div>
                <div class="metric-val" style="font-size: 13px;">{timestamp}</div>
            </div>
        </div>

        <h2>Detected Threat Signals & Scoring Breakdown</h2>
        {signals_html}

        <h2>Matched GTIG Threat Indicators (IOCs)</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Indicator Value</th>
                    <th>Intelligence Context</th>
                </tr>
            </thead>
            <tbody>
                {iocs_html}
            </tbody>
        </table>

        <h2>MITRE ATT&CK Framework Mapping</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Technique Name</th>
                    <th>Tactic</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {mitre_html}
            </tbody>
        </table>

        <h2>Extracted & Decoded Obfuscated Payloads</h2>
        {decoded_html}

        <div class="footer">
            Generated by LOSTKEYS Threat Detector — B.Sc. Cybersecurity Defensive Analysis Engine | 100% Static Offline Analysis
        </div>
    </div>
</body>
</html>
"""
    return html_template
