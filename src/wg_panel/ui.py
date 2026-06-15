from flask import session

from .core import _lang
from .i18n import t

FAVICON = '<link rel="icon" href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'><text y=\'.9em\' font-size=\'90\'>🔒</text></svg>">'

def page_head(title="VPN Panel"):
    return f'<title>{title} | VPN Panel</title>\n{FAVICON}\n'

CSS = """
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* ── Reset ── */
*{box-sizing:border-box;margin:0;padding:0}

/* ── Dark theme (default) ── */
:root{
  --bg:#0d1117;--card:#161b22;--border:#30363d;--border2:#21262d;
  --text:#c9d1d9;--text2:#8b949e;--head:#e6edf3;
  --accent:#58a6ff;--input-bg:#0d1117;
  --ok-bg:#0d4429;--ok:#3fb950;
  --err-bg:#3d0c0c;--err:#f85149;
  --pend-bg:#3d2b00;--pend:#d29922;
  --admin-bg:#1a2f5e;--admin:#79c0ff;
  --stat-bg:#0d1117;
  --btn-s-bg:#21262d;--btn-s-border:#30363d;
}

/* ── Light theme ── */
@media(prefers-color-scheme:light){
  :root{
    --bg:#f6f8fa;--card:#ffffff;--border:#d0d7de;--border2:#eaeef2;
    --text:#1f2328;--text2:#656d76;--head:#1f2328;
    --accent:#0969da;--input-bg:#ffffff;
    --ok-bg:#dafbe1;--ok:#1a7f37;
    --err-bg:#ffebe9;--err:#cf222e;
    --pend-bg:#fff8c5;--pend:#9a6700;
    --admin-bg:#ddf4ff;--admin:#0550ae;
    --stat-bg:#f6f8fa;
    --btn-s-bg:#f6f8fa;--btn-s-border:#d0d7de;
  }
}

body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:var(--bg);color:var(--text);min-height:100vh;padding:24px 16px;
     overflow-x:hidden}
.wrap{max-width:560px;margin:0 auto;min-width:0}
.wide{max-width:860px;margin:0 auto;min-width:0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;
      padding:28px;margin-bottom:20px;overflow:hidden}
h1{color:var(--accent);font-size:22px;margin-bottom:4px}
h2{color:var(--head);font-size:17px;margin-bottom:14px}
.sub{color:var(--text2);font-size:13px;margin-bottom:20px}
input[type=text],input[type=password],input[type=number],select{
  width:100%;padding:10px 12px;background:var(--input-bg);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-size:16px;margin-bottom:14px;
  -webkit-appearance:none}
input:focus,select:focus{border-color:var(--accent);outline:none}
label{display:block;color:var(--text2);font-size:13px;margin-bottom:5px}
.btn{display:inline-block;padding:10px 18px;border:none;border-radius:6px;
     font-size:14px;cursor:pointer;text-decoration:none;text-align:center;
     color:#fff;transition:opacity .15s;
     -webkit-tap-highlight-color:transparent}
.btn:hover{opacity:.85}
.g{background:#238636}.b{background:#1f6feb}.r{background:#da3633}
.y{background:#9e6a03}.s{background:var(--btn-s-bg);border:1px solid var(--btn-s-border);color:var(--text)}
.btn-full{width:100%;display:block;padding:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;align-items:center}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}
.tag-ok{background:var(--ok-bg);color:var(--ok)}
.tag-pend{background:var(--pend-bg);color:var(--pend)}
.tag-admin{background:var(--admin-bg);color:var(--admin)}
.msg-ok{color:var(--ok);font-size:13px;margin-bottom:12px;padding:8px 12px;
        background:var(--ok-bg);border-radius:6px}
.msg-err{color:var(--err);font-size:13px;margin-bottom:12px;padding:8px 12px;
         background:var(--err-bg);border-radius:6px}
.conf{background:var(--stat-bg);border:1px solid var(--border);border-radius:6px;padding:12px;
      font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;
      max-height:260px;overflow-y:auto;margin:12px 0;color:var(--text)}
.qr{text-align:center;margin:16px 0}
.qr img{max-width:260px;width:100%;background:#fff;padding:10px;border-radius:8px}
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -4px}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:340px}
th{text-align:left;color:var(--text2);font-weight:500;padding:8px 10px;
   border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid var(--border2);vertical-align:middle}
tr:last-child td{border-bottom:none}
.nav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
hr{border:none;border-top:1px solid var(--border);margin:20px 0}
.stat-box{text-align:center;padding:16px 20px;background:var(--stat-bg);
          border:1px solid var(--border);border-radius:8px;flex:1;min-width:90px}
.stat-num{font-size:28px;font-weight:700;color:var(--accent)}
.stat-lbl{color:var(--text2);font-size:12px;margin-top:2px}

/* ── Mobile ── */
@media(max-width:600px){
  body{padding:16px 12px}
  .card{padding:18px 14px}
  .nav{gap:6px;overflow-x:auto;flex-wrap:wrap;-webkit-overflow-scrolling:touch}
  .nav .btn{font-size:13px;padding:9px 12px;flex:0 0 auto;white-space:nowrap}
  h1{font-size:20px}
  .stat-box{padding:12px 10px}
  .stat-num{font-size:22px}
  td,th{padding:7px 6px}
  .btn{padding:8px 12px;font-size:13px}
}
</style>
"""

def flash_html():
    msgs = ""
    for cat, msg in (session.pop("_flashes", None) or []):
        cls = "msg-ok" if cat == "ok" else "msg-err"
        msgs += f'<div class="{cls}">{msg}</div>'
    return msgs

# ─── Pages ────────────────────────────────────────────────────────────────────
def login_page(lang):
    return page_head("VPN Panel") + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>🔒 VPN Panel</h1>
  <p class="sub">{t("login_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" id="login-form" autocomplete="on">
    <label for="username">{t("login_user", lang)}</label>
    <input type="text" id="username" name="u" autocomplete="username" required autofocus>
    <label for="password">{t("login_pass", lang)}</label>
    <input type="password" id="password" name="p" autocomplete="current-password" required>
    <button class="btn g btn-full" type="submit">{t("login_btn", lang)}</button>
  </form>
  <hr>
  <div style="text-align:center;display:flex;gap:8px;justify-content:center">
    <a href="/register" class="btn s">{t("login_create", lang)}</a>
    <a href="/forgot" class="btn s">{t("login_forgot", lang)}</a>
  </div>
</div></div>
"""

def register_page(lang):
    return page_head("Register") + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>📝 Register</h1>
  <p class="sub">{t("reg_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" autocomplete="on">
    <label>{t("reg_user", lang)}</label>
    <input type="text" id="username" name="u" pattern="[a-z0-9-]+" required autofocus
           autocomplete="username" title="Lowercase letters, numbers, dashes only">
    <label>{t("reg_pass", lang)}</label>
    <input type="password" id="new-password" name="p" minlength="8" required autocomplete="new-password">
    <label>{t("reg_confirm", lang)}</label>
    <input type="password" name="p2" required autocomplete="new-password">
    <div style="background:rgba(255,200,0,0.07);border:1px solid rgba(255,200,0,0.25);border-radius:8px;padding:12px 14px;margin:12px 0;font-size:12px;color:var(--fg);line-height:1.6">
      {t("reg_terms", lang)}
    </div>
    <label style="display:flex;align-items:flex-start;gap:8px;font-size:13px;cursor:pointer;margin-bottom:4px">
      <input type="checkbox" name="agree" required style="margin-top:3px;flex-shrink:0">
      <span>{t("reg_agree", lang)}</span>
    </label>
    <button class="btn g btn-full" type="submit">{t("reg_btn", lang)}</button>
  </form>
  <hr>
  <div style="text-align:center">
    <a href="/login" class="btn s">{t("reg_back", lang)}</a>
  </div>
</div></div>
"""

def pending_page(lang):
    return page_head(t("pend_title", lang)) + CSS + f"""
<div class="wrap" style="padding-top:80px">
<div class="card" style="text-align:center">
  <h1>⏳ {t("pend_title", lang)}</h1>
  <p class="sub" style="margin-bottom:20px">{t("pend_sub", lang)}</p>
  <a href="/logout" class="btn r">{t("pend_logout", lang)}</a>
</div></div>
"""

def nav_bar(is_admin=False):
    lang = _lang()
    admin_link = (f'<a href="/admin" class="btn b">{t("nav_admin", lang)}</a>'
                  f'<a href="/traffic" class="btn b">{t("nav_traffic", lang)}</a>') if is_admin else ''
    return f"""<div class="nav">
  <a href="/dashboard" class="btn b">{t("nav_devices", lang)}</a>
  <a href="/add" class="btn g">{t("nav_add", lang)}</a>
  {admin_link}
  <a href="/logout" class="btn r" style="margin-left:auto;flex-shrink:0">{t("nav_logout", lang)}</a>
</div>"""

def forgot_page(lang):
    return page_head("Forgot Password") + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>🔑 Forgot Password</h1>
  <p class="sub">{t("forgot_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST">
    <label>{t("login_user", lang)}</label>
    <input type="text" name="u" required autofocus>
    <button class="btn g btn-full" type="submit">{t("forgot_btn", lang)}</button>
  </form>
  <hr>
  <div style="text-align:center"><a href="/login" class="btn s">{t("forgot_back", lang)}</a></div>
</div></div>
"""

def reset_page(lang, username):
    if lang == "ru":
        sub = f"Выберите новый пароль для <b>{username}</b>."
    else:
        sub = f"Choose a new password for <b>{username}</b>."
    return page_head(t("reset_title", lang)) + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>🔑 {t("reset_title", lang)}</h1>
  <p class="sub">{sub}</p>
  {{{{flash}}}}
  <form method="POST">
    <label>{t("reset_new_pw", lang)}</label>
    <input type="password" name="p" minlength="8" required autofocus>
    <label>{t("reset_conf_pw", lang)}</label>
    <input type="password" name="p2" required>
    <button class="btn g btn-full" type="submit">{t("reset_btn", lang)}</button>
  </form>
</div></div>
"""
