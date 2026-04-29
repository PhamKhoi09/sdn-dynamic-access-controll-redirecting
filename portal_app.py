import json
import os
import time
import ipaddress
from flask import Flask, request, render_template_string


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_FILE = os.path.join(BASE_DIR, 'sessions.json')
SESSION_TTL_SECONDS = 300

USERS = {
    "admin":     {"password": "admin123",  "role": "admin"},
    "employee1": {"password": "emp123",    "role": "employee"},
    "guest1":    {"password": "guest123",  "role": "guest"},
}

ROLE_LABEL = {
    "admin":    ("Admin",    "#1a7"),
    "employee": ("Employee", "#17a"),
    "guest":    ("Guest",    "#888"),
}

app = Flask(__name__)


# ── Session helpers ───────────────────────────────────────────────────────────

def load_sessions():
    try:
        with open(SESSION_FILE, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    sessions = data.get('sessions', {})
    now = time.time()
    cleaned = {}
    for ip, entry in sessions.items():
        if not isinstance(entry, dict):
            continue
        try:
            if now < float(entry.get('expires_at', 0)):
                cleaned[ip] = entry
        except (TypeError, ValueError):
            continue
    return cleaned


def save_sessions(sessions):
    tmp_path = SESSION_FILE + '.tmp'
    with open(tmp_path, 'w') as f:
        json.dump({'sessions': sessions}, f, indent=4)
    os.replace(tmp_path, SESSION_FILE)


def detect_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        candidate = forwarded_for.split(',')[0].strip()
        if candidate:
            return candidate
    return request.remote_addr or ''


def validate_ip(value):
    return str(ipaddress.ip_address(value))


# ── HTML template ─────────────────────────────────────────────────────────────

PAGE = """
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SDN Auth Portal</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 48px auto; padding: 0 20px; background:#f4f6f8; }
    h1   { color: #333; }
    .card { background:#fff; border:1px solid #ddd; border-radius:12px; padding:24px; margin-bottom:20px; }
    label { display:block; margin-bottom:4px; font-weight:bold; font-size:0.9em; color:#555; }
    input { padding:10px; width:100%; box-sizing:border-box; margin-bottom:14px; border:1px solid #ccc; border-radius:6px; }
    button { padding:10px 20px; border:0; border-radius:8px; cursor:pointer; font-size:0.95em; }
    .btn-primary { background:#2196F3; color:#fff; }
    .btn-danger  { background:#e53935; color:#fff; }
    .ok   { color:#1a7; font-weight:bold; }
    .warn { color:#b60; font-weight:bold; }
    .badge { display:inline-block; padding:2px 10px; border-radius:10px; color:#fff; font-size:0.8em; font-weight:bold; }
    table { width:100%; border-collapse:collapse; }
    th,td { padding:10px 12px; border-bottom:1px solid #eee; text-align:left; font-size:0.9em; }
    th { background:#f0f0f0; }
    .hint { color:#999; font-size:0.8em; }
  </style>
</head>
<body>
  <h1>SDN Authentication Portal</h1>
  <p class="hint">IP ph&aacute;t hi&ecirc;n: <strong>{{ client_ip }}</strong> &mdash; Ph&acirc;n quy&ecirc;n &amp; &#273;i&#7873;u h&#432;&#7899;ng traffic (SDN redirect controller)</p>

  {% if message %}<p class="ok">{{ message }}</p>{% endif %}
  {% if error   %}<p class="warn">{{ error }}</p>{% endif %}

  <!-- Login form -->
  <div class="card">
    <h2>&#128274; X&aacute;c th&#7921;̣c</h2>
    <form method="post" action="/authenticate">
      <label for="username">T&agrave;i kho&#7843;n</label>
      <input id="username" name="username" placeholder="admin / employee1 / guest1" autocomplete="username">
      <label for="password">M&#7853;t kh&#7849;u</label>
      <input id="password" name="password" type="password" autocomplete="current-password">
      <label for="ip">IP c&#7847;n x&aacute;c th&#7921;c (m&#7863;c &#273;&#7883;nh: IP c&#7911;a b&#7841;n)</label>
      <input id="ip" name="ip" placeholder="{{ client_ip }}" value="{{ client_ip }}">
      <button type="submit" class="btn-primary">X&aacute;c th&#7921;c &rarr;</button>
    </form>
    <p class="hint">Demo: admin/admin123 &bull; employee1/emp123 &bull; guest1/guest123 &bull; TTL={{ ttl }}s</p>
  </div>

  <!-- Logout form -->
  <div class="card">
    <h2>&#128275; &#272;&#259;ng xu&#7845;t</h2>
    <form method="post" action="/logout">
      <label for="lip">IP c&#7847;n &#273;&#259;ng xu&#7845;t</label>
      <input id="lip" name="ip" placeholder="{{ client_ip }}" value="{{ client_ip }}">
      <button type="submit" class="btn-danger">&#272;&#259;ng xu&#7845;t</button>
    </form>
  </div>

  <!-- Active sessions table -->
  <div class="card">
    <h2>&#128203; Active Sessions (redirect role_by_ip)</h2>
    {% if sessions %}
    <table>
      <tr><th>IP</th><th>User</th><th>Role</th><th>H&#7871;t h&#7841;n</th></tr>
      {% for ip, entry in sessions.items() %}
      {% set lbl = role_label.get(entry.get('role','guest'), ('Unknown','#aaa')) %}
      <tr>
        <td><code>{{ ip }}</code></td>
        <td>{{ entry.get('username', '?') }}</td>
        <td><span class="badge" style="background:{{ lbl[1] }}">{{ lbl[0] }}</span></td>
        <td>{{ (entry.get('expires_at', 0) | int) }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p class="hint">Ch&#432;a c&oacute; session n&agrave;o.</p>
    {% endif %}
  </div>
</body>
</html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    client_ip = detect_client_ip()
    sessions = load_sessions()
    return render_template_string(PAGE, client_ip=client_ip, sessions=sessions,
                                  message=None, error=None, ttl=SESSION_TTL_SECONDS,
                                  role_label=ROLE_LABEL)


@app.route('/authenticate', methods=['POST'])
def authenticate():
    client_ip   = detect_client_ip()
    ip_override = request.form.get('ip', '').strip()
    username    = request.form.get('username', '').strip()
    password    = request.form.get('password', '').strip()

    target_ip = ip_override if ip_override else client_ip
    try:
        normalized_ip = validate_ip(target_ip)
    except ValueError:
        sessions = load_sessions()
        return render_template_string(PAGE, client_ip=client_ip, sessions=sessions,
                                      message=None, error='IP không hợp lệ.',
                                      ttl=SESSION_TTL_SECONDS, role_label=ROLE_LABEL), 400

    user = USERS.get(username)
    if not user or user['password'] != password:
        sessions = load_sessions()
        return render_template_string(PAGE, client_ip=client_ip, sessions=sessions,
                                      message=None, error='Sai tài khoản hoặc mật khẩu.',
                                      ttl=SESSION_TTL_SECONDS, role_label=ROLE_LABEL), 401

    role = user['role']
    sessions = load_sessions()
    sessions[normalized_ip] = {
        'username':   username,
        'role':       role,
        'expires_at': time.time() + SESSION_TTL_SECONDS,
    }
    save_sessions(sessions)

    message = f'Đã xác thực: {normalized_ip} → role={role} (hết hạn sau {SESSION_TTL_SECONDS}s)'
    return render_template_string(PAGE, client_ip=client_ip, sessions=sessions,
                                  message=message, error=None,
                                  ttl=SESSION_TTL_SECONDS, role_label=ROLE_LABEL)


@app.route('/logout', methods=['POST'])
def logout():
    client_ip   = detect_client_ip()
    ip_override = request.form.get('ip', '').strip()
    target_ip   = ip_override if ip_override else client_ip

    sessions = load_sessions()
    try:
        normalized_ip = validate_ip(target_ip)
        sessions.pop(normalized_ip, None)
        save_sessions(sessions)
        message = f'Đã đăng xuất: {normalized_ip}'
    except ValueError:
        message = 'IP không hợp lệ'

    return render_template_string(PAGE, client_ip=client_ip, sessions=sessions,
                                  message=message, error=None,
                                  ttl=SESSION_TTL_SECONDS, role_label=ROLE_LABEL)


@app.route('/api/sessions', methods=['GET'])
def api_sessions():
    """JSON endpoint: SDN controller (or any client) can poll active sessions."""
    return app.response_class(
        response=json.dumps({'sessions': load_sessions()}),
        status=200,
        mimetype='application/json',
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
