from flask import session
from markupsafe import escape

from .core import _lang
from .i18n import t
from .security import csrf_input

FAVICON = '<link rel="icon" href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'><text y=\'.9em\' font-size=\'90\'>🔒</text></svg>">'

def page_head(title="VPN Panel"):
    return (
        f'<title>{escape(title)} | VPN Panel</title>\n'
        '<meta name="color-scheme" content="dark light">\n'
        '<meta name="theme-color" content="#091423">\n'
        f"{FAVICON}\n"
    )

CSS = """
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* ── Reset and design tokens ── */
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07111f;--bg-deep:#050b14;--card:#0f1d2f;--card-raised:#13263d;
  --border:#27415e;--border-strong:#3b5e80;--border2:#1c3149;
  --text:#e6eef7;--text2:#91a6ba;--head:#f7fbff;--accent:#75baff;
  --accent-strong:#2e86e5;--input-bg:#0a1728;--fg:var(--text);
  --ok-bg:#103d31;--ok:#6de0a4;--err-bg:#421f2a;--err:#ff9aac;
  --pend-bg:#443419;--pend:#ffd27c;--admin-bg:#1e365f;--admin:#a6ceff;
  --upload:#ff9d82;
  --stat-bg:#0a1728;--btn-s-bg:#15283e;--btn-s-border:#2d4966;
  --shadow:0 18px 48px rgba(0,0,0,.24);--radius:14px;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
}
@media(prefers-color-scheme:light){
  :root{
    --bg:#f1f6fb;--bg-deep:#e6eef7;--card:#ffffff;--card-raised:#f7fbff;
    --border:#cfdae6;--border-strong:#aebfd0;--border2:#e4ebf2;
    --text:#1d2a38;--text2:#5d7184;--head:#102236;--accent:#0969da;
    --accent-strong:#0758b8;--input-bg:#ffffff;--stat-bg:#f3f7fb;
    --ok-bg:#daf6e7;--ok:#18794e;--err-bg:#ffebee;--err:#b42342;
    --pend-bg:#fff3d2;--pend:#8b5e13;--admin-bg:#e3f0ff;--admin:#15559b;
    --upload:#c2412d;
    --btn-s-bg:#f3f7fb;--btn-s-border:#c8d5e2;
    --shadow:0 16px 36px rgba(32,62,91,.11);
  }
}

html{background:var(--bg-deep);scroll-behavior:smooth}
body{font-family:var(--font);background:
     radial-gradient(circle at 10% -10%,rgba(66,145,220,.18),transparent 34rem),
     radial-gradient(circle at 100% 0%,rgba(87,96,201,.12),transparent 30rem),var(--bg);
     color:var(--text);min-height:100vh;padding:32px 18px 56px;overflow-x:hidden;
     font-size:15px;line-height:1.5}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:600px;margin:0 auto;min-width:0}
.wide{max-width:1100px;margin:0 auto;min-width:0}
.auth-wrap{padding-top:7vh}
.card{background:linear-gradient(145deg,rgba(255,255,255,.025),transparent 44%),var(--card);
      border:1px solid var(--border);border-radius:var(--radius);padding:30px;
      margin-bottom:22px;overflow:hidden;box-shadow:var(--shadow)}
.auth-card{max-width:520px;margin:0 auto;padding:34px}
.page-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
              flex-wrap:wrap;margin-bottom:22px}
.page-title{margin-bottom:5px}
.eyebrow{display:block;color:var(--text2);font-size:11px;font-weight:700;letter-spacing:.14em;
         text-transform:uppercase;margin-bottom:8px}
h1{color:var(--head);font-size:clamp(24px,3vw,31px);line-height:1.15;letter-spacing:-.02em;margin-bottom:5px}
h2{color:var(--head);font-size:18px;line-height:1.25;margin-bottom:14px}
.sub{color:var(--text2);font-size:14px;margin-bottom:22px;line-height:1.55}
.auth-title{color:var(--accent);font-size:28px}
.auth-links{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.stack{display:grid;gap:2px}
.field-help{color:var(--text2);font-size:12px;line-height:1.5}
.field-help-spaced{margin-top:14px}
.section-hint{margin-bottom:10px}
.section-actions{margin-bottom:14px}
.terms{background:rgba(255,200,0,.07);border:1px solid rgba(255,200,0,.26);
       border-radius:10px;padding:14px 16px;margin:14px 0;font-size:12px;line-height:1.6}
.check-row{display:flex;align-items:flex-start;gap:10px;font-size:13px;cursor:pointer;margin-bottom:16px}
.check-row input{margin-top:4px;flex:0 0 auto}
label{display:block;color:var(--text2);font-size:13px;font-weight:600;margin-bottom:7px}
input[type=text],input[type=password],input[type=number],select{
  width:100%;padding:11px 13px;background:var(--input-bg);border:1px solid var(--border);
  border-radius:9px;color:var(--text);font:inherit;font-size:16px;margin-bottom:16px;
  -webkit-appearance:none;transition:border-color .15s,box-shadow .15s,background .15s}
input::placeholder{color:var(--text2);opacity:.72}
input[type=checkbox]{accent-color:var(--accent-strong);width:18px;height:18px}
input:focus,select:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(86,164,255,.2)}
input:focus-visible,select:focus-visible,.btn:focus-visible,a:focus-visible,.conf:focus-visible{outline:3px solid rgba(117,186,255,.55);outline-offset:2px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:42px;
     padding:10px 17px;border:1px solid transparent;border-radius:9px;font-size:14px;
     font-weight:700;cursor:pointer;text-decoration:none;text-align:center;color:#fff;
     transition:transform .15s,box-shadow .15s,background .15s,opacity .15s;
     -webkit-tap-highlight-color:transparent}
.btn:hover{opacity:1;transform:translateY(-1px);text-decoration:none;box-shadow:0 7px 16px rgba(0,0,0,.18)}
.btn:active{transform:translateY(0);box-shadow:none}
.g{background:linear-gradient(135deg,#238b5b,#1d744e)}
.b{background:linear-gradient(135deg,#2e86e5,#2167b9)}
.r{background:linear-gradient(135deg,#d24b5d,#ad3047)}
.y{background:linear-gradient(135deg,#b4771c,#916014)}
.s{background:var(--btn-s-bg);border-color:var(--btn-s-border);color:var(--text)}
.btn-full{width:100%;display:flex;padding:12px}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.inline{display:inline}
.compact-input{width:72px!important;padding:7px 8px!important;margin:0 4px 0 0!important}
.center-card{text-align:center}
.tag{display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border-radius:999px;
     font-size:12px;line-height:1.2;font-weight:700;white-space:nowrap}
.tag-ok{background:var(--ok-bg);color:var(--ok)}
.tag-pend{background:var(--pend-bg);color:var(--pend)}
.tag-admin{background:var(--admin-bg);color:var(--admin)}
.msg-ok,.msg-err{font-size:13px;margin-bottom:16px;padding:11px 14px;border-radius:9px;
        border:1px solid transparent;line-height:1.45}
.msg-ok{color:var(--ok);background:var(--ok-bg);border-color:rgba(109,224,164,.26)}
.msg-err{color:var(--err);background:var(--err-bg);border-color:rgba(255,154,172,.26)}
.empty-state{color:var(--text2);padding:24px 16px;text-align:center}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',monospace;font-size:.92em}
.owner{color:var(--text2)}
.device-name{color:var(--accent)}
.history{color:var(--text2);font-size:12px;line-height:1.65}
.cell-down{color:var(--ok)}
.cell-up{color:var(--upload)}
.conf{background:var(--stat-bg);border:1px solid var(--border);border-radius:9px;padding:14px;
      font-family:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',monospace;font-size:11px;
      white-space:pre-wrap;word-break:break-all;max-height:280px;overflow-y:auto;margin:14px 0;color:var(--text)}
.qr{text-align:center;margin:20px 0}
.qr img{max-width:280px;width:100%;background:#fff;padding:12px;border-radius:12px;box-shadow:0 10px 24px rgba(0,0,0,.2)}
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -6px;padding:0 6px}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;min-width:520px}
table.compact-table{min-width:0;table-layout:fixed}
table.compact-table th:first-child,table.compact-table td:first-child{width:34%}
table.compact-table td{overflow-wrap:anywhere}
th{text-align:left;color:var(--text2);font-size:11px;font-weight:700;letter-spacing:.05em;
   text-transform:uppercase;padding:11px 12px;border-bottom:1px solid var(--border)}
td{padding:13px 12px;border-bottom:1px solid var(--border2);vertical-align:middle}
tbody tr{transition:background .15s}
tbody tr:hover{background:rgba(117,186,255,.05)}
tr:last-child td{border-bottom:none}
.table-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.table-actions .btn{min-height:34px;padding:7px 10px;font-size:12px}
.nav{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:24px;padding:7px;
     background:rgba(15,29,47,.76);border:1px solid var(--border);border-radius:13px;
     box-shadow:0 10px 28px rgba(0,0,0,.13);backdrop-filter:blur(12px)}
.nav-main,.nav-account{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.nav-account{margin-left:auto}
.nav .btn{min-height:38px;padding:8px 13px;font-size:13px}
hr{border:none;border-top:1px solid var(--border);margin:24px 0}
.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:20px}
.stat-box{text-align:left;padding:17px 18px;background:linear-gradient(145deg,rgba(255,255,255,.025),transparent),var(--stat-bg);
          border:1px solid var(--border);border-radius:11px;min-width:0}
.price-preview{margin-bottom:14px}
.stat-num{font-size:clamp(22px,3vw,30px);line-height:1.1;font-weight:800;color:var(--accent);letter-spacing:-.02em}
.stat-lbl{color:var(--text2);font-size:12px;margin-top:7px;line-height:1.35}
.safe-card{background:linear-gradient(145deg,rgba(117,186,255,.055),transparent 58%),var(--stat-bg);
           border:1px solid var(--border);border-radius:11px;padding:17px 18px;margin:16px 0 24px}
.safe-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap}
.safe-card-title{margin:0 0 8px}
.safe-toggle{display:flex;align-items:center;gap:10px;margin:2px 0 0;cursor:pointer;color:var(--text);font-size:13px}
.safe-toggle input{margin:0;flex:0 0 auto}
.safe-help{color:var(--text2);font-size:12px;line-height:1.55;margin:13px 0 16px;max-width:780px}
.conf{cursor:pointer;user-select:all}
.copy-toast{display:none;color:var(--ok);font-size:13px;margin:8px 0}
.download-btn{margin-bottom:10px}

@media(max-width:760px){
  body{padding:22px 13px 40px}
  .card{padding:22px 17px}
  .auth-wrap{padding-top:3vh}
  .auth-card{padding:25px 19px}
  .nav{gap:6px;margin-bottom:18px}
  .nav-main,.nav-account{width:100%}
  .nav-account{margin-left:0}
  .nav .btn{flex:1 1 auto;white-space:nowrap}
  .nav-account form,.nav-account form .btn{width:100%}
  .metric-grid{grid-template-columns:1fr;gap:9px}
  .stat-box{text-align:left;padding:14px 16px}
  .page-heading{margin-bottom:17px}
  h1{font-size:24px}
  table{min-width:470px}
  td,th{padding:10px 8px}
  .btn{min-height:40px;padding:9px 12px;font-size:13px}
}
@media(prefers-reduced-motion:reduce){
  *,*:before,*:after{scroll-behavior:auto!important;transition:none!important}
}
</style>
"""

def flash_html():
    msgs = ""
    for cat, msg in (session.pop("_flashes", None) or []):
        cls = "msg-ok" if cat == "ok" else "msg-err"
        msgs += f'<div class="{cls}">{escape(msg)}</div>'
    return msgs

# ─── Pages ────────────────────────────────────────────────────────────────────
def login_page(lang):
    return page_head("VPN Panel") + CSS + f"""
<div class="wrap auth-wrap">
<div class="card auth-card">
  <span class="eyebrow">{t("auth_secure", lang)}</span>
  <h1 class="auth-title">🔒 VPN Panel</h1>
  <p class="sub">{t("login_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" id="login-form" class="stack" autocomplete="on">
    {csrf_input()}
    <label for="username">{t("login_user", lang)}</label>
    <input type="text" id="username" name="u" autocomplete="username" required autofocus>
    <label for="password">{t("login_pass", lang)}</label>
    <input type="password" id="password" name="p" autocomplete="current-password" required>
    <button class="btn g btn-full" type="submit">{t("login_btn", lang)}</button>
  </form>
  <hr>
  <div class="auth-links">
    <a href="/register" class="btn s">{t("login_create", lang)}</a>
    <a href="/forgot" class="btn s">{t("login_forgot", lang)}</a>
  </div>
</div></div>
"""

def register_page(lang):
    return page_head("Register") + CSS + f"""
<div class="wrap auth-wrap">
<div class="card auth-card">
  <span class="eyebrow">{t("auth_create", lang)}</span>
  <h1>📝 Register</h1>
  <p class="sub">{t("reg_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" class="stack" autocomplete="on">
    {csrf_input()}
    <label for="username">{t("reg_user", lang)}</label>
    <input type="text" id="username" name="u" pattern="[a-z0-9-]+" required autofocus
           minlength="3" maxlength="32" autocomplete="username"
           title="Lowercase letters, numbers, dashes only">
    <label for="telegram_username">{t("reg_telegram", lang)}</label>
    <input type="text" id="telegram_username" name="telegram_username" pattern="@?[A-Za-z0-9_]{{5,32}}"
           minlength="5" maxlength="33" autocomplete="off" placeholder="@username" required>
    <label for="new-password">{t("reg_pass", lang)}</label>
    <input type="password" id="new-password" name="p" minlength="8" required autocomplete="new-password">
    <label for="confirm-password">{t("reg_confirm", lang)}</label>
    <input type="password" id="confirm-password" name="p2" required autocomplete="new-password">
    <div class="terms">
      {t("reg_terms", lang)}
    </div>
    <label class="check-row" for="agree">
      <input type="checkbox" id="agree" name="agree" required>
      <span>{t("reg_agree", lang)}</span>
    </label>
    <button class="btn g btn-full" type="submit">{t("reg_btn", lang)}</button>
  </form>
  <hr>
  <div class="auth-links">
    <a href="/login" class="btn s">{t("reg_back", lang)}</a>
  </div>
</div></div>
"""

def pending_page(lang):
    return page_head(t("pend_title", lang)) + CSS + f"""
<div class="wrap auth-wrap">
<div class="card auth-card center-card">
  <h1>⏳ {t("pend_title", lang)}</h1>
  <p class="sub">{t("pend_sub", lang)}</p>
  <form method="POST" action="/logout">
    {csrf_input()}
    <button type="submit" class="btn r">{t("pend_logout", lang)}</button>
  </form>
</div></div>
"""

def nav_bar(is_admin=False):
    lang = _lang()
    admin_link = (f'<a href="/admin" class="btn b">{t("nav_admin", lang)}</a>'
                  f'<a href="/traffic" class="btn b">{t("nav_traffic", lang)}</a>') if is_admin else ''
    return f"""<div class="nav">
  <div class="nav-main">
    <a href="/dashboard" class="btn b">{t("nav_devices", lang)}</a>
    <a href="/add" class="btn g">{t("nav_add", lang)}</a>
    {admin_link}
  </div>
  <div class="nav-account">
  <form method="POST" action="/logout">
    {csrf_input()}
    <button type="submit" class="btn r">{t("nav_logout", lang)}</button>
  </form>
  </div>
</div>"""

def forgot_page(lang):
    return page_head("Forgot Password") + CSS + f"""
<div class="wrap auth-wrap">
<div class="card auth-card">
  <span class="eyebrow">{t("auth_recovery", lang)}</span>
  <h1>🔑 Forgot Password</h1>
  <p class="sub">{t("forgot_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" class="stack">
    {csrf_input()}
    <label for="username">{t("login_user", lang)}</label>
    <input type="text" id="username" name="u" required autofocus>
    <button class="btn g btn-full" type="submit">{t("forgot_btn", lang)}</button>
  </form>
  <hr>
  <div class="auth-links"><a href="/login" class="btn s">{t("forgot_back", lang)}</a></div>
</div></div>
"""

def reset_page(lang, username):
    username = escape(username)
    if lang == "ru":
        sub = f"Выберите новый пароль для <b>{username}</b>."
    else:
        sub = f"Choose a new password for <b>{username}</b>."
    return page_head(t("reset_title", lang)) + CSS + f"""
<div class="wrap auth-wrap">
<div class="card auth-card">
  <span class="eyebrow">{t("auth_recovery", lang)}</span>
  <h1>🔑 {t("reset_title", lang)}</h1>
  <p class="sub">{sub}</p>
  {{{{flash}}}}
  <form method="POST" class="stack">
    {csrf_input()}
    <label for="new-password">{t("reset_new_pw", lang)}</label>
    <input type="password" id="new-password" name="p" minlength="8" required autofocus>
    <label for="confirm-password">{t("reset_conf_pw", lang)}</label>
    <input type="password" id="confirm-password" name="p2" required>
    <button class="btn g btn-full" type="submit">{t("reset_btn", lang)}</button>
  </form>
</div></div>
"""
