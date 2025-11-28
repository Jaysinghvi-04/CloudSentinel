import sys
import os
import datetime
from flask import Flask, render_template, request, jsonify

# Add parent dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_engine.aws_scanner import scan_aws

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        ak = request.form.get('access_key')
        sk = request.form.get('secret_key')
        
        # Run the scan logic
        report = scan_aws(ak, sk)
        
        # Add metadata for the UI (Simulating "Processing Logs")
        report['scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report['logs'] = [
            f"[INFO] Initializing scan at {report['scan_time']}...",
            "[INFO] Authenticating with AWS Credentials...",
            "[CHECK] CIS Benchmark 1.1: Root User Check...",
            "[CHECK] CIS Benchmark 2.3: S3 Bucket Encryption...",
            f"[RESULT] Scan completed with Score: {report['score']}/100"
        ]
        
        # Calculate stats for Charts
        safe_count = len([x for x in report['findings'] if x['status'] == 'SAFE'])
        risk_count = len([x for x in report['findings'] if x['status'] == 'RISK'])
        
        return render_template('dashboard.html', report=report, safe=safe_count, risk=risk_count)
    
    return render_template('scanner_form.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)