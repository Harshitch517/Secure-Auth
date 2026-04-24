#ifndef ASSETS_H
#define ASSETS_H

// Premium Modern CSS
static const char *ASSET_CSS_MAIN = 
":root {\n"
"  --primary: #6366f1;\n"
"  --primary-hover: #4f46e5;\n"
"  --bg: #0f172a;\n"
"  --card-bg: rgba(30, 41, 59, 0.7);\n"
"  --text: #f8fafc;\n"
"  --text-muted: #94a3b8;\n"
"  --border: rgba(255, 255, 255, 0.1);\n"
"  --error-bg: rgba(239, 68, 68, 0.1);\n"
"  --error-text: #f87171;\n"
"}\n"
"* { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', sans-serif; }\n"
"body { background: var(--bg); color: var(--text); overflow-x: hidden; }\n"
".auth-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: radial-gradient(circle at top right, #1e1b4b, #0f172a); }\n"
".auth-card { background: var(--card-bg); backdrop-filter: blur(12px); padding: 2.5rem; border-radius: 1.5rem; border: 1px solid var(--border); width: 100%; max-width: 400px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); transform: translateY(0); transition: all 0.3s ease; }\n"
".error-box { background: var(--error-bg); border: 1px solid var(--error-text); color: var(--error-text); padding: 0.75rem; border-radius: 0.75rem; margin-bottom: 1.5rem; font-size: 0.875rem; text-align: center; display: none; }\n"
".error-box.visible { display: block; animation: shake 0.4s ease-in-out; }\n"
"@keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }\n"
"h1 { font-size: 1.875rem; font-weight: 700; margin-bottom: 0.5rem; text-align: center; background: linear-gradient(to right, #818cf8, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }\n"
"p.subtitle { color: var(--text-muted); text-align: center; margin-bottom: 2rem; font-size: 0.875rem; }\n"
".form-group { margin-bottom: 1.25rem; }\n"
"label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.5rem; color: var(--text-muted); }\n"
"input { width: 100%; padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border); border-radius: 0.75rem; color: white; transition: all 0.2s; }\n"
"input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); }\n"
".btn { width: 100%; padding: 0.75rem; background: var(--primary); color: white; border: none; border-radius: 0.75rem; font-weight: 600; cursor: pointer; transition: all 0.2s; margin-top: 1rem; }\n"
".btn:hover { background: var(--primary-hover); transform: scale(1.02); }\n"
".footer-link { text-align: center; margin-top: 1.5rem; font-size: 0.875rem; color: var(--text-muted); }\n"
".footer-link a { color: var(--primary); text-decoration: none; font-weight: 500; }\n"
".footer-link a:hover { text-decoration: underline; }\n";

// Modern Interactive JS
static const char *ASSET_JS_MAIN = 
"document.addEventListener('DOMContentLoaded', () => {\n"
"  const err = document.querySelector('.error-box');\n"
"  if (err && err.innerText.trim().length > 0) err.classList.add('visible');\n"
"});\n";

// Base Template
static const char *TEMPLATE_BASE = 
"<!DOCTYPE html>\n"
"<html lang='en'>\n"
"<head>\n"
"  <meta charset='UTF-8'>\n"
"  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
"  <title>{{ title }}</title>\n"
"  <style>{{ css }}</style>\n"
"  <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap' rel='stylesheet'>\n"
"</head>\n"
"<body>\n"
"  {{ content }}\n"
"  <script>{{ js }}</script>\n"
"</body>\n"
"</html>";

// Login Template
static const char *TEMPLATE_LOGIN = 
"<div class='auth-container'>\n"
"  <div class='auth-card'>\n"
"    <h1>Secure Access</h1>\n"
"    <p class='subtitle'>Please enter your credentials to continue</p>\n"
"    <div class='error-box'>{{ error }}</div>\n"
"    <form method='POST'>\n"
"      <div class='form-group'>\n"
"        <label>Email Address</label>\n"
"        <input type='email' name='email' placeholder='name@company.com' required>\n"
"      </div>\n"
"      <div class='form-group'>\n"
"        <label>Password</label>\n"
"        <input type='password' name='password' placeholder='••••••••' required>\n"
"      </div>\n"
"      <button type='submit' class='btn'>Sign In</button>\n"
"    </form>\n"
"    <div class='footer-link'>\n"
"      Don't have an account? <a href='/auth/register'>Create one</a>\n"
"    </div>\n"
"  </div>\n"
"</div>";

// Register Template
static const char *TEMPLATE_REGISTER = 
"<div class='auth-container'>\n"
"  <div class='auth-card'>\n"
"    <h1>Join Us</h1>\n"
"    <p class='subtitle'>Create your secure account today</p>\n"
"    <div class='error-box'>{{ error }}</div>\n"
"    <form method='POST'>\n"
"      <div class='form-group'>\n"
"        <label>Username</label>\n"
"        <input type='text' name='username' placeholder='johndoe' required>\n"
"      </div>\n"
"      <div class='form-group'>\n"
"        <label>Email Address</label>\n"
"        <input type='email' name='email' placeholder='name@company.com' required>\n"
"      </div>\n"
"      <div class='form-group'>\n"
"        <label>Password</label>\n"
"        <input type='password' name='password' placeholder='••••••••' required>\n"
"      </div>\n"
"      <button type='submit' class='btn'>Create Account</button>\n"
"    </form>\n"
"    <div class='footer-link'>\n"
"      Already have an account? <a href='/auth/login'>Sign in</a>\n"
"    </div>\n"
"  </div>\n"
"</div>";

// Dashboard Template
static const char *TEMPLATE_DASHBOARD = 
"<div class='auth-container' style='align-items: flex-start; padding-top: 5rem;'>\n"
"  <div class='auth-card' style='max-width: 800px;'>\n"
"    <h1>Admin Dashboard</h1>\n"
"    <p class='subtitle'>System Overview & User Management</p>\n"
"    <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 2rem;'>\n"
"      <div style='background: rgba(15, 23, 42, 0.4); padding: 1.5rem; border-radius: 1rem; border: 1px solid var(--border);'>\n"
"        <h3 style='font-size: 0.875rem; color: var(--text-muted);'>Active Users</h3>\n"
"        <p style='font-size: 2rem; font-weight: 700; margin-top: 0.5rem;'>1,284</p>\n"
"      </div>\n"
"      <div style='background: rgba(15, 23, 42, 0.4); padding: 1.5rem; border-radius: 1rem; border: 1px solid var(--border);'>\n"
"        <h3 style='font-size: 0.875rem; color: var(--text-muted);'>System Status</h3>\n"
"        <p style='font-size: 2rem; font-weight: 700; color: #10b981; margin-top: 0.5rem;'>Operational</p>\n"
"      </div>\n"
"    </div>\n"
"    <a href='/auth/logout' class='btn' style='display: block; text-decoration: none; text-align: center; margin-top: 2rem; background: transparent; border: 1px solid var(--primary); color: var(--primary);'>Logout</a>\n"
"  </div>\n"
"</div>";

#endif
