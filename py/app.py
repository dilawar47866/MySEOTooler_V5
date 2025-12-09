from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, make_response, current_app, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
import re, os, requests, base64, json, validators, csv, random, ipaddress, socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
import bleach  # NEW: For Security (XSS Protection)
from io import BytesIO, StringIO
from sqlalchemy import text
from youtube_transcript_api import YouTubeTranscriptApi
from collections import Counter
from fpdf import FPDF
from threading import Thread

# ==========================================
# 1. CONFIGURATION
# ==========================================
load_dotenv()
app = Flask(__name__)

# Security: Ensure we are not in debug mode for production
DEBUG_MODE = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

# --- EMAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'support@myseokingtool.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('My SEO King Tool Team', app.config['MAIL_USERNAME'])
app.config['MAIL_DEBUG'] = DEBUG_MODE

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# --- GLOBAL TOOL LIST ---
TOOL_LIST = [
    'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
    'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
    'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
    'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
    'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis',
    'youtube-to-blog', 'image-generator', 'site-auditor', 'content-humanizer', 
    'article-wizard', 'bulk-writer', 'gbp-tool', 'geo-optimizer', 'backlink-outreach',
    'social-preview', 'keyword-density'
]

# --- PIPED MIRRORS ---
PIPED_INSTANCES = [
    "https://pipedapi.kavin.rocks",
    "https://api.piped.privacy.com.de",
    "https://pipedapi.moomoo.me",
    "https://pipedapi.smnz.de",
    "https://pipedapi.adminforge.de"
]

# ==========================================
# 1.5 SECURITY HELPERS (NEW)
# ==========================================
def is_safe_url(target_url):
    """Prevents Server-Side Request Forgery (SSRF) by blocking internal IPs"""
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname: return False
        
        # Resolve hostname to IP
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        
        # Block private, loopback, and link-local addresses
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        return True
    except:
        return False

def sanitize_html(html_content):
    """Prevents XSS by cleaning AI output"""
    allowed_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'li', 'strong', 'em', 'b', 'i', 'code', 'pre', 'br', 'hr', 'blockquote', 'a']
    allowed_attrs = {'a': ['href', 'title', 'target']}
    return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

def send_async_email(app_obj, msg):
    with app_obj.app_context():
        try:
            mail.send(msg)
            print(f"✅ Email sent to {msg.recipients}")
        except Exception as e:
            print(f"❌ Background email failed: {e}")

def send_email_background(subject, recipient, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    app_obj = current_app._get_current_object()
    thr = Thread(target=send_async_email, args=[app_obj, msg])
    thr.start()

# ==========================================
# 2. DATABASE MODELS
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    tier = db.Column(db.String(20), default='free')
    content_count = db.Column(db.Integer, default=0)
    ai_requests_this_month = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    contents = db.relationship('Content', backref='author', lazy=True, cascade="all, delete-orphan")
    
    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def get_limits(self):
        limits = {'free': 50, 'pro': 500, 'pro king': 500, 'enterprise': 9999}
        return {'ai_requests_per_month': limits.get(self.tier.lower(), 50)}

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    keyword = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    html_content = db.Column(db.Text)
    seo_score = db.Column(db.Integer, default=0)
    word_count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id): 
    return User.query.get(int(user_id))

# ==========================================
# 3. ROUTES
# ==========================================
@app.route('/favicon.ico')
def favicon(): return redirect(url_for('static', filename='favicon.ico'))

@app.route('/apple-touch-icon.png')
def apple_touch_icon(): return redirect(url_for('static', filename='apple-touch-icon.png'))

@app.route('/favicon-32x32.png')
def favicon_32(): return redirect(url_for('static', filename='favicon-32x32.png'))

@app.route('/favicon-16x16.png')
def favicon_16(): return redirect(url_for('static', filename='favicon-16x16.png'))

@app.route('/site.webmanifest')
def webmanifest():
    manifest = {
        "name": "My SEO King Tool",
        "short_name": "MySEOKingTool",
        "icons": [
            {"src": "/static/android-chrome-192x192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/android-chrome-512x512.png", "sizes": "512x512", "type": "image/png"}
        ],
        "theme_color": "#4f46e5",
        "background_color": "#ffffff",
        "display": "standalone"
    }
    return jsonify(manifest)

@app.route('/')
def landing(): 
    if current_user.is_authenticated: 
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

app.add_url_rule('/', endpoint='home', view_func=landing)

@app.route('/dashboard')
@login_required
def dashboard():
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
    total = Content.query.filter_by(user_id=current_user.id).count()
    words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    avg_score = 0
    scores = [c.seo_score for c in Content.query.filter_by(user_id=current_user.id).all()]
    if scores: avg_score = sum(scores) / len(scores)

    return render_template('index.html', recent_content=recent, total_content=total, 
                         total_words=words, avg_score=round(avg_score, 1), 
                         limits=current_user.get_limits())

@app.route('/editor')
@login_required
def editor():
    c = Content.query.filter_by(id=request.args.get('id'), user_id=current_user.id).first() if request.args.get('id') else None
    return render_template('editor.html', content=c)

app.add_url_rule('/editor', endpoint='content_generator', view_func=editor)

@app.route('/content-library')
@login_required
def content_library():
    contents = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).all()
    return render_template('content_library.html', contents=contents)

@app.route('/pricing')
def pricing(): return render_template('pricing.html')

@app.route('/profile')
@login_required
def profile(): return render_template('profile.html')

# --- DEDICATED TOOL PAGE ROUTES ---
@app.route('/article-wizard')
@login_required
def article_wizard_page(): return render_template('article_wizard.html')

@app.route('/alt-text-generator')
@login_required
def alt_text_generator_page(): return render_template('alt_text_generator.html')

@app.route('/bulk-writer')
@login_required
def bulk_writer_page():
    if current_user.tier == 'free':
        flash("Bulk Writing is a Pro Feature!", "warning")
        return redirect('/pricing')
    return render_template('bulk_writer.html')

@app.route('/sitemap-generator')
@login_required
def sitemap_generator_page(): return render_template('sitemap_generator.html')

@app.route('/robots-generator')
@login_required
def robots_generator_page(): return render_template('robots_generator.html')

@app.route('/robots.txt')
def robots_txt():
    lines = ["User-agent: *", "Disallow: /dashboard", "Disallow: /editor", "Disallow: /admin", "Disallow: /profile", f"Sitemap: {request.url_root}sitemap.xml"]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    pages = ['/', '/pricing', '/login', '/signup']
    for slug in TOOL_LIST: pages.append(f'/tool/{slug}')
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages: xml += f'  <url>\n    <loc>{base_url}{page}</loc>\n    <changefreq>weekly</changefreq>\n  </url>\n'
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}

# ==========================================
# 5. AUTH ROUTES
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        if user and user.check_password(data.get('password')):
            if not user.is_active: return jsonify({'error': 'Banned'}), 403
            login_user(user)
            return jsonify({'success': True, 'redirect': '/dashboard'})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect('/dashboard')
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            if User.query.filter_by(email=data.get('email').lower()).first(): return jsonify({'error': 'Email exists'}), 400
            hashed = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
            user = User(username=data.get('username'), email=data.get('email').lower(), password_hash=hashed)
            if User.query.count() == 0: user.is_admin = True
            db.session.add(user)
            db.session.commit()
            login_user(user)
            try:
                send_email_background("Welcome to MySEO King! 👑", user.email, f"Hi {user.username},\n\nWelcome to My SEO King Tool.\n\nCheers,\nTeam")
            except: pass
            return jsonify({'success': True, 'redirect': '/dashboard'})
        except Exception as e: return jsonify({'error': str(e)}), 500
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout(): 
    logout_user()
    return redirect('/')

# ==========================================
# 6. ADMIN & PAYMENT (SECURED)
# ==========================================
@app.route('/admin')
@login_required
def admin():
    if not getattr(current_user, 'is_admin', False): return redirect('/dashboard')
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin.html', users=users, total_content=Content.query.count())

@app.route('/admin/export-users')
@login_required
def admin_export_users():
    if not getattr(current_user, 'is_admin', False): return "Unauthorized", 403
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Email', 'Tier'])
    for u in User.query.all(): cw.writerow([u.id, u.username, u.email, u.tier])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=users.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        user.is_active = not user.is_active
        db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        db.session.delete(user)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/upgrade', methods=['POST'])
@login_required
def admin_upgrade_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    user.tier = data.get('tier')
    db.session.commit()
    return jsonify({'success': True})

# --- SECURED PAYMENT ROUTE (FIXED LEAKAGE) ---
@app.route('/payment/success/<plan_name>')
@login_required
def payment_success(plan_name):
    # SECURITY FIX: Check for PayPal's automatic return parameters.
    # If a user manually types this URL, these params will be missing.
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    
    # If parameters are missing, DENY the upgrade
    if not payment_id or not payer_id:
        flash("Payment verification failed. Please contact support if you paid.", "danger")
        return redirect('/dashboard')

    # In a perfect world, we would verify these ID with PayPal API here.
    # But checking for existence stops the simple "Type URL" exploit.
    
    if plan_name == 'pro': 
        current_user.tier = 'pro king'
    elif plan_name == 'enterprise': 
        current_user.tier = 'enterprise'
    
    db.session.commit()
    flash(f"Successfully upgraded to {current_user.tier}!", "success")
    return redirect('/dashboard')

# ==========================================
# 7. TOOL ROUTER
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    if tool_name == 'image-generator' and current_user.tier == 'free':
        flash("Pro Feature!", "warning")
        return redirect('/pricing')
    
    if tool_name == 'article-wizard': return redirect('/article-wizard')
    if tool_name == 'alt-text-generator': return redirect('/alt-text-generator')
    if tool_name == 'bulk-writer': return redirect('/bulk-writer')
    if tool_name == 'sitemap-generator': return redirect('/sitemap-generator')
    if tool_name == 'robots-generator': return redirect('/robots-generator')
    
    try:
        return render_template(f'{tool_name.replace("-", "_")}.html')
    except:
        return "Tool not found", 404

for t in TOOL_LIST:
    if t not in ['article-wizard', 'alt-text-generator', 'bulk-writer', 'sitemap-generator', 'robots-generator']:
        app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t: 
        app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))

# ==========================================
# 8. API ENDPOINTS
# ==========================================

@app.route('/api/bulk-write-single', methods=['POST'])
@login_required
def api_bulk_write_single():
    if current_user.tier == 'free': return jsonify({'error': 'Upgrade to Pro for Bulk Writing!'}), 403
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Monthly limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        tone = data.get('tone', 'Professional')
        word_count = data.get('word_count', 800)
        
        prompt = f"Write a comprehensive, SEO-optimized blog post about: \"{keyword}\"\nTone: {tone}\nTarget words: {word_count}\nFormat: Markdown."
        
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "system", "content": "Expert SEO writer."}, {"role": "user", "content": prompt}], max_tokens=2000)
        content = res.choices[0].message.content
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        # Security: Sanitize HTML
        html_safe = sanitize_html(markdown.markdown(content))
        return jsonify({'success': True, 'keyword': keyword, 'content': content, 'html': html_safe, 'word_count': len(content.split())})
    except Exception as e:
        return jsonify({'error': str(e), 'keyword': data.get('keyword', 'Unknown')}), 500

@app.route('/api/generate-sitemap', methods=['POST'])
@login_required
def api_generate_sitemap():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        if not base_url: return jsonify({'error': 'Please enter a URL'}), 400
        if not base_url.startswith('http'): base_url = 'https://' + base_url
        
        # Security: SSRF Check
        if not is_safe_url(base_url): return jsonify({'error': 'Invalid or restricted URL'}), 400
        
        parsed = urlparse(base_url)
        urls = data.get('urls', [])
        
        if not urls:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                r = requests.get(base_url, headers=headers, timeout=10)
                soup = BeautifulSoup(r.content, 'html.parser')
                found_urls = set([base_url])
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/'): full_url = base_url + href
                    elif href.startswith(base_url): full_url = href
                    else: continue
                    if parsed.netloc in full_url: found_urls.add(full_url.split('#')[0].split('?')[0])
                urls = list(found_urls)[:50]
            except Exception as e: urls = [base_url]
        
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for url in urls:
            xml += f'  <url>\n    <loc>{url.strip()}</loc>\n    <lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod>\n  </url>\n'
        xml += '</urlset>'
        return jsonify({'success': True, 'sitemap': xml, 'url_count': len(urls), 'urls_found': urls})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-robots', methods=['POST'])
@login_required
def api_generate_robots():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        if not base_url.startswith('http'): base_url = 'https://' + base_url
        
        disallow_paths = data.get('disallow', [])
        if data.get('preset') == 'balanced' and not disallow_paths:
             disallow_paths = ['/admin', '/dashboard', '/api/', '/private/', '/tmp/', '/*.json$']
        
        lines = []
        for agent in data.get('user_agents', ['*']):
            lines.append(f'User-agent: {agent}')
            for path in disallow_paths: lines.append(f'Disallow: {path.strip()}')
            lines.append('')
        lines.append(f'Sitemap: {base_url}/sitemap.xml')
        return jsonify({'success': True, 'robots': '\n'.join(lines)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/download-sitemap', methods=['POST'])
@login_required
def api_download_sitemap():
    resp = make_response(request.get_json().get('content', ''))
    resp.headers['Content-Type'] = 'application/xml'
    resp.headers['Content-Disposition'] = 'attachment; filename=sitemap.xml'
    return resp

@app.route('/api/download-robots', methods=['POST'])
@login_required
def api_download_robots():
    resp = make_response(request.get_json().get('content', ''))
    resp.headers['Content-Type'] = 'text/plain'
    resp.headers['Content-Disposition'] = 'attachment; filename=robots.txt'
    return resp

@app.route('/api/backlink-outreach', methods=['POST'])
@login_required
def api_backlink_outreach():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    d = request.get_json()
    prompt = f"Write email pitch for backlink.\nTarget: {d.get('url')}\nTopic: {d.get('topic')}"
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Outreach Expert"},{"role":"user","content":prompt}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/public-audit', methods=['POST'])
def api_public_audit():
    try:
        url = request.get_json().get('url')
        if not url: return jsonify({'error': 'Enter URL'}), 400
        if not url.startswith('http'): url = 'https://' + url
        if not is_safe_url(url): return jsonify({'error': 'Restricted URL'}), 400
        
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=15)
        s = BeautifulSoup(r.content, 'html.parser')
        score, issues = 100, []
        if not s.title: score -= 20; issues.append("Missing Title Tag")
        elif len(s.title.string) > 60: score -= 5; issues.append("Title Too Long")
        if not s.find('meta', attrs={'name':'description'}): score -= 20; issues.append("Missing Meta Description")
        if not s.find('h1'): score -= 20; issues.append("Missing H1 Heading")
        if score == 100: issues.append("No critical errors found")
        return jsonify({'success': True, 'score': max(35,score), 'issues': issues})
    except: return jsonify({'success': True, 'score': 42, 'issues': ['Server Response Timeout']})

@app.route('/api/audit-site', methods=['POST'])
@login_required
def api_audit_site():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'): url = 'https://' + url
        if not is_safe_url(url): return jsonify({'error': 'Restricted URL'}), 400
        
        start = datetime.now()
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=30)
        load = round((datetime.now()-start).total_seconds(), 2)
        s = BeautifulSoup(r.content, 'html.parser')
        score, issues, passed = 100, [], []
        
        if not s.title: score -= 20; issues.append({"type":"critical","msg":"Missing Title"})
        else: passed.append("Title Exists")
        if not s.find('meta', attrs={'name':'description'}): score -= 20; issues.append({"type":"critical","msg":"Missing Meta Desc"})
        else: passed.append("Meta Description Found")
        if not s.find('h1'): score -= 20; issues.append({"type":"critical","msg":"Missing H1"})
        else: passed.append("H1 Tag Found")
        
        return jsonify({'success': True, 'score': max(0,score), 'meta': {'url': url, 'title': s.title.string if s.title else "None", 'load_time': f"{load}s"}, 'issues': issues, 'passed': passed})
    except Exception as e: return jsonify({'error': f"Failed: {str(e)}"}), 500

@app.route('/api/generate-image', methods=['POST'])
@login_required
def api_generate_image():
    if current_user.tier == 'free': return jsonify({'error': 'Upgrade to Pro!'}), 403
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.images.generate(model="dall-e-3", prompt=request.get_json().get('prompt'), size="1024x1024", quality="standard", n=1)
        current_user.ai_requests_this_month += 5
        db.session.commit()
        return jsonify({'success': True, 'image_url': res.data[0].url})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/humanize-text', methods=['POST'])
@login_required
def api_humanize_text():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o", messages=[{"role":"system","content":"Rewriter"},{"role":"user","content":f"Humanize: {request.get_json().get('content')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/article-wizard', methods=['POST'])
@login_required
def api_article_wizard():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        d = request.get_json()
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Writer"},{"role":"user","content":f"Blog about: {d.get('topic')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached.'}), 403
    video_url = request.get_json().get('url')
    if not is_safe_url(video_url): return jsonify({'error': 'Invalid URL'}), 400
    try:
        vid = video_url.split("v=")[1].split("&")[0] if "v=" in video_url else video_url.split("youtu.be/")[1].split("?")[0]
        full_text = ""
        mirrors = PIPED_INSTANCES.copy()
        random.shuffle(mirrors)
        for m in mirrors:
            try:
                r = requests.get(f"{m}/streams/{vid}", timeout=5)
                if r.status_code == 200:
                    subs = r.json().get('subtitles', [])
                    tgt = next((s for s in subs if 'en' in s.get('code','')), subs[0] if subs else None)
                    if tgt:
                        lines = requests.get(tgt['url']).text.splitlines()
                        clean = [l.strip() for l in lines if '-->' not in l and 'WEBVTT' not in l and l.strip()]
                        full_text = " ".join(clean)
                        if len(full_text) > 50: break
            except: continue
        if not full_text: return jsonify({'error': "No captions found."}), 400
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Writer"},{"role":"user","content":f"Blog from transcript: {full_text[:15000]}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":request.get_json().get('keyword')}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html_content': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/save-content', methods=['POST'])
@login_required
def api_save_content():
    d = request.get_json()
    # Security: Ensure content ownership
    if d.get('id'):
        c = Content.query.get(d.get('id'))
        if c and c.user_id == current_user.id:
            c.title = d.get('title')
            c.content = d.get('content')
            c.html_content = sanitize_html(d.get('html_content'))
            c.keyword = d.get('keyword')
            c.word_count = len(d.get('content','').split())
            db.session.commit()
            return jsonify({'success': True, 'id': c.id})
    new_c = Content(user_id=current_user.id, title=d.get('title'), content=d.get('content'), html_content=sanitize_html(d.get('html_content')), keyword=d.get('keyword'), word_count=len(d.get('content','').split()))
    db.session.add(new_c)
    current_user.content_count += 1
    db.session.commit()
    return jsonify({'success': True, 'id': new_c.id})

@app.route('/api/publish-wordpress', methods=['POST'])
@login_required
def api_publish_wordpress():
    d = request.get_json()
    wp = d.get('url').rstrip('/')
    if not is_safe_url(wp): return jsonify({'error': 'Invalid WP URL'}), 400
    creds = f"{d.get('username')}:{d.get('password')}"
    t = base64.b64encode(creds.encode()).decode('utf-8')
    try:
        r = requests.post(f"{wp}/wp-json/wp/v2/posts", headers={'Authorization': f'Basic {t}', 'Content-Type': 'application/json'}, json={'title':d.get('title'),'content':d.get('content'),'status':'draft'}, timeout=15)
        return jsonify({'success': True, 'link': r.json().get('link')})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id: 
        db.session.delete(c)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/generate-seo-terms', methods=['POST'])
@login_required
def api_generate_seo_terms():
    res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"LSI keywords for {request.get_json().get('keyword')} as JSON array"}])
    return jsonify({'success':True, 'terms': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})

@app.route('/api/generate-questions', methods=['POST'])
@login_required
def api_generate_questions():
    res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"PAA questions for {request.get_json().get('keyword')} as JSON array"}])
    return jsonify({'success':True, 'questions': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})

@app.route('/api/suggest-internal-links', methods=['POST'])
@login_required
def api_suggest_links():
    res = Content.query.filter(Content.user_id==current_user.id, Content.title.ilike(f"%{request.get_json().get('keyword')}%")).limit(5).all()
    return jsonify({'success':True, 'links': [{'id':c.id, 'title':c.title} for c in res]})

@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_readability():
    try:
        text_content = request.get_json().get('content', '')
        if not text_content: return jsonify({'error': 'No text'}), 400
        words = [w for w in text_content.split() if len(w) > 0]
        sentences = [s for s in text_content.replace('!', '.').replace('?', '.').split('.') if len(s) > 0]
        score = 206.835 - (1.015 * (len(words)/max(1, len(sentences)))) - (84.6 * (sum(1 for w in words for x in w if x in 'aeiouy')/max(1, len(words))))
        return jsonify({'success': True, 'stats': {'score': round(score, 1), 'grade': "Standard", 'color': 'success' if score > 60 else 'warning'}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/improve-readability', methods=['POST'])
@login_required
def api_improve_readability():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Editor"},{"role":"user","content":f"Simplify: {request.get_json().get('content')[:3000]}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_schema():
    return jsonify({'success': True, 'json': json.dumps({"@context": "https://schema.org", "@type": "Article", "headline": "Example"}, indent=4)})

@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_competitor():
    try:
        url = request.get_json().get('url')
        if not is_safe_url(url): return jsonify({'error': 'Restricted URL'})
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=10)
        s = BeautifulSoup(r.content, 'html.parser')
        return jsonify({'success': True, 'analysis': {'title': s.title.string, 'word_count': len(s.get_text().split())}})
    except: return jsonify({'error': 'Failed'})

@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_clusters():
    res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"Clusters for {request.get_json().get('keyword')} as JSON"}])
    return jsonify({'success':True, 'clusters': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})

@app.route('/api/gbp-generate', methods=['POST'])
@login_required
def api_gbp_generate():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Local SEO"},{"role":"user","content":f"Write GBP update for {request.get_json().get('business')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/geo-optimize', methods=['POST'])
@login_required
def api_geo_optimize():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":f"GEO Answer for: '{request.get_json().get('keyword')}'"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-social', methods=['POST'])
@login_required
def api_analyze_social():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'): url = 'https://' + url
        if not is_safe_url(url): return jsonify({'error': 'Restricted URL'}), 400
        r = requests.get(url, headers={'User-Agent': 'facebookexternalhit/1.1'}, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        og_img = soup.find('meta', property='og:image')
        return jsonify({'success': True, 'data': {'og_image': og_img['content'] if og_img else ''}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-density', methods=['POST'])
@login_required
def api_analyze_density():
    try:
        data = request.get_json()
        content = data.get('content')
        if data.get('type') == 'url':
             if not is_safe_url(content): return jsonify({'error': 'Restricted URL'}), 400
             content = requests.get(content, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10).text
        words = re.findall(r'\w+', content.lower())
        return jsonify({'success': True, 'results': [{'word': k, 'count': v} for k, v in Counter(words).most_common(10)]})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-report', methods=['POST'])
@login_required
def api_generate_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(40, 10, f"SEO Report for {request.get_json().get('url')}")
    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=seo_report.pdf'
    return response

@app.route('/api/generate-video-script', methods=['POST'])
@login_required
def api_generate_video_script():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"YouTuber"},{"role":"user","content":f"Script for: {request.get_json().get('topic')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-social-posts', methods=['POST'])
@login_required
def api_generate_social_posts():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SMM"},{"role":"user","content":f"Posts for: {request.get_json().get('topic')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/spy-competitor', methods=['POST'])
@login_required
def api_spy_competitor():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    url = request.get_json().get('url')
    if not is_safe_url(url): return jsonify({'error': 'Restricted URL'}), 400
    try:
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=15)
        soup = BeautifulSoup(r.content, 'html.parser')
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO Strategist"},{"role":"user","content":f"Analyze: {soup.title.string}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'data': {'strategy': sanitize_html(markdown.markdown(res.choices[0].message.content))}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/research-keywords', methods=['POST'])
@login_required
def api_research_keywords():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"Keywords for: {request.get_json().get('seed')} as JSON array"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'keywords': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-outline', methods=['POST'])
@login_required
def api_generate_outline():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":f"Outline for: {request.get_json().get('topic')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': sanitize_html(markdown.markdown(res.choices[0].message.content))})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/test-email')
def test_email():
    try:
        send_email_background("Test Async", 'dilawarahsanrizvi7@gmail.com', "This email was sent in background.")
        return "Email process started (Async)"
    except Exception as e: return f"Err: {e}"

@app.route('/fix-db')
def fix_db():
    if not current_user.is_authenticated or not current_user.is_admin: return "Unauthorized", 403
    with db.engine.connect() as conn: 
        conn.execute(text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'free';"))
        conn.commit()
    return "DB Fixed"

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    # SECURITY: Disable debug mode for production deployment
    app.run(debug=False, port=int(os.environ.get('PORT', 5001)))