import json
import os
import re
import ssl
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo

# ----------------- SMTP & Alert Configuration -----------------
SMTP_SERVER = "mail.konstantinfosolutions.com"
SMTP_PORT = 587
SMTP_USER = "kiplserver@konstantinfosolutions.com"
SMTP_PASSWORD = "RockShox@7499"
FROM_EMAIL = "kiplserver@konstantinfosolutions.com"
RECIPIENTS = ["hiteshjaipur@gmail.com", "hitesh@konstantinfosolutions.com"]

# ----------------- Monitored Targets -----------------
HOSTS = [
    ("202.157.76.22", "Hitesh Firewall -94"),
    ("202.157.76.20", "My-Meeting Desk Server-135"),
    ("202.157.76.19", "Jenkins Server -143"),
    ("202.157.76.18", "Node Server -234"),
    ("202.157.76.17", "GateWay- DataInfosys"),
    ("111.93.246.174", "Tata Communication-Wan2")
]

# State file saved directly in the writable Documents directory
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor_state.json")
SUMMARY_INTERVAL_SECONDS = 7200  # 2 Hours

# ----------------- State Helpers -----------------
def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_summary_epoch": 0, "host_states": {}}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ----------------- a-Shell Ping Helper -----------------
def ping_host(ip):
    """
    Executes a-Shell's native ping tool instead of raw Python sockets.
    Sends 2 packets and parses response output.
    """
    try:
        # Runs 2 pings
        cmd = f"ping -c 2 {ip}"
        with os.popen(cmd) as stream:
            output = stream.read()

        # Check if packets were returned
        if "bytes from" in output or " 0% packet loss" in output or " 0.0% packet loss" in output:
            # Extract round-trip average latency: min/avg/max
            rtt_match = re.search(r"=\s*[0-9.]+/([0-9.]+)/", output)
            if rtt_match:
                latency = f"{rtt_match.group(1)} ms"
            else:
                time_match = re.search(r"time=([0-9.]+)\s*ms", output)
                latency = f"{time_match.group(1)} ms" if time_match else "UP"
            return True, latency
        else:
            return False, "No Response"
    except Exception:
        return False, "No Response"

# ----------------- SMTP Mailer -----------------
def send_html_email(subject, html_content):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Host Monitor <{FROM_EMAIL}>"
    msg["To"] = ", ".join(RECIPIENTS)
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    context = ssl.create_default_context()
    
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(FROM_EMAIL, RECIPIENTS, msg.as_string())

# ----------------- Monitoring Logic -----------------
def run_monitor(force_report=False):
    ist_time = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %I:%M:%S %p IST")
    state = load_state()
    host_states = state.get("host_states", {})
    last_summary = state.get("last_summary_epoch", 0)

    total_hosts = len(HOSTS)
    up_count = 0
    down_count = 0
    table_rows = []

    print(f"[*] Starting checks at {ist_time}...")

    for ip, alias in HOSTS:
        previous_state = host_states.get(ip, "UNKNOWN")
        is_up, info = ping_host(ip)

        if is_up:
            current_state = "UP"
            badge = '<span style="display:inline-block;padding:6px 14px;font-weight:bold;font-size:14px;color:#fff;background-color:#28a745;border-radius:4px;">UP</span>'
            up_count += 1
            print(f"  [+] [{alias}] {ip} is UP ({info})")
        else:
            current_state = "DOWN"
            badge = '<span style="display:inline-block;padding:6px 14px;font-weight:bold;font-size:14px;color:#fff;background-color:#dc3545;border-radius:4px;">DOWN</span>'
            down_count += 1
            print(f"  [-] [{alias}] {ip} is DOWN")

        table_rows.append(f"""
        <tr>
            <td style="padding:12px 16px;border-bottom:1px solid #e0e0e0;font-size:16px;font-weight:600;color:#2c3e50;">{alias}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e0e0e0;font-family:monospace;font-size:15px;">{ip}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e0e0e0;text-align:center;">{badge}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e0e0e0;font-size:14px;color:#555;">{info}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #e0e0e0;font-size:14px;color:#555;">{ist_time}</td>
        </tr>""")

        # Immediate Failure Alert (only fires if it was previously UP or first recorded as DOWN)
        if current_state == "DOWN" and previous_state == "UP":
            print(f"  [!] Sending Failure Alert for {alias}...")
            sub = f"[CRITICAL ALERT] Host DOWN: {alias} ({ip})"
            html = f"""<div style="font-family:Arial,sans-serif;max-width:650px;padding:22px;border:2px solid #dc3545;border-radius:8px;background:#fff5f5;">
                <h2 style="color:#dc3545;margin-top:0;">🚨 Host Connectivity Lost</h2>
                <table style="width:100%;background:#fff;border-collapse:collapse;font-size:15px;">
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">Host:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{alias}</td></tr>
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">IP:</td><td style="padding:8px 12px;font-family:monospace;border-bottom:1px solid #eee;">{ip}</td></tr>
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">Status:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;"><span style="background:#dc3545;color:#fff;padding:3px 8px;border-radius:4px;">DOWN</span></td></tr>
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">Detected:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{ist_time}</td></tr>
                </table>
            </div>"""
            try:
                send_html_email(sub, html)
            except Exception as e:
                print(f"  [x] Failed to send alert email: {e}")

        # Immediate Recovery Alert
        elif current_state == "UP" and previous_state == "DOWN":
            print(f"  [!] Sending Recovery Alert for {alias}...")
            sub = f"[RECOVERY] Host BACK ONLINE: {alias} ({ip})"
            html = f"""<div style="font-family:Arial,sans-serif;max-width:650px;padding:22px;border:2px solid #28a745;border-radius:8px;background:#f6fff8;">
                <h2 style="color:#28a745;margin-top:0;">✅ Host Connectivity Restored</h2>
                <table style="width:100%;background:#fff;border-collapse:collapse;font-size:15px;">
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">Host:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{alias}</td></tr>
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">IP:</td><td style="padding:8px 12px;font-family:monospace;border-bottom:1px solid #eee;">{ip}</td></tr>
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">Status:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;"><span style="background:#28a745;color:#fff;padding:3px 8px;border-radius:4px;">UP</span></td></tr>
                    <tr><td style="padding:8px 12px;font-weight:bold;border-bottom:1px solid #eee;">Latency:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;color:#28a745;font-weight:bold;">{info}</td></tr>
                </table>
            </div>"""
            try:
                send_html_email(sub, html)
            except Exception as e:
                print(f"  [x] Failed to send recovery email: {e}")

        host_states[ip] = current_state

    # 2-Hour Summary Report
    now_epoch = int(datetime.now().timestamp())
    time_diff = now_epoch - last_summary

    if time_diff >= SUMMARY_INTERVAL_SECONDS or force_report:
        print("[*] Generating 2-Hour Summary Email...")
        sub = f"[Status Report] Host Connectivity Tracking - {ist_time}"
        summary_html = f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f6f8;padding:20px;">
        <div style="max-width:820px;margin:auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,0.1);">
            <div style="background:#1a252f;padding:16px 20px;color:#fff;">
                <h2 style="margin:0;font-size:20px;">Host Connectivity Status Report</h2>
                <p style="margin:4px 0 0;font-size:13px;color:#cfd8dc;">Checked: {ist_time}</p>
            </div>
            <div style="padding:12px 20px;background:#f8f9fa;border-bottom:1px solid #eee;font-size:14px;">
                <strong>Total:</strong> {total_hosts} &nbsp;|&nbsp;
                <strong style="color:#28a745;">UP:</strong> {up_count} &nbsp;|&nbsp;
                <strong style="color:#dc3545;">DOWN:</strong> {down_count}
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:14px;">
                <thead>
                    <tr style="background:#eef2f5;">
                        <th style="padding:10px 14px;text-align:left;">Host</th>
                        <th style="padding:10px 14px;text-align:left;">IP</th>
                        <th style="padding:10px 14px;text-align:center;">Status</th>
                        <th style="padding:10px 14px;text-align:left;">Latency</th>
                        <th style="padding:10px 14px;text-align:left;">Time</th>
                    </tr>
                </thead>
                <tbody>{''.join(table_rows)}</tbody>
            </table>
        </div></body></html>"""
        try:
            send_html_email(sub, summary_html)
            last_summary = now_epoch
            print("[✔] Summary email sent.")
        except Exception as e:
            print(f"  [x] Failed to send summary email: {e}")

    state["host_states"] = host_states
    state["last_summary_epoch"] = last_summary
    save_state(state)
    print("[✔] Check cycle complete and state saved.")

if __name__ == "__main__":
    run_monitor(force_report=False)