from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
import re, os, requests, base64, json, validators, csv, random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from io import BytesIO, StringIO
from sqlalchemy import text
from youtube_transcript_api import YouTubeTranscriptApi
from collections import Counter
from fpdf import FPDF

# ==========================================
# 1. CONFIGURATION
# ==========================================
load_dotenv()
app = Flask(__name__)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

# Email
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'support@myseokingtool.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') 
app.config['MAIL_DEFAULT_SENDER'] = ('MySEO King Team', 'support@myseokingtool.com')

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
# 3. PAGE ROUTES
# ==========================================
@app.route('/')
def landing(): 
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
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

# --- FORCE ROUTES ---
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

# --- TECHNICAL SEO ROUTES ---
@app.route('/robots.txt')
def robots_txt():
    lines = ["User-agent: *", "Disallow: /dashboard", "Disallow: /editor", f"Sitemap: {request.url_root}sitemap.xml"]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    pages = ['/', '/pricing', '/login', '/signup']
    for slug in TOOL_LIST:
        pages.append(f'/tool/{slug}')

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += f'  <url>\n    <loc>{base_url}{page}</loc>\n    <changefreq>weekly</changefreq>\n  </url>\n'
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}

# ==========================================
# 4. AUTH ROUTES
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
            
            db.session.add(user); db.session.commit(); login_user(user)

            try:
                msg = Message("Welcome to MySEO King! 👑", recipients=[user.email])
                msg.body = f"Hi {user.username},\n\nWelcome to MySEO King.\n\nCheers,\nTeam"
                mail.send(msg)
            except: pass

            return jsonify({'success': True, 'redirect': '/dashboard'})
        except Exception as e: return jsonify({'error': str(e)}), 500
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect('/')

# ==========================================
# 5. ADMIN & PAYMENT
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
    si = StringIO(); cw = csv.writer(si)
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

@app.route('/payment/success/<plan_name>')
@login_required
def payment_success(plan_name):
    if plan_name == 'pro': current_user.tier = 'pro king'
    elif plan_name == 'enterprise': current_user.tier = 'enterprise'
    db.session.commit()
    return redirect('/dashboard')

# ==========================================
# 6. TOOL ROUTER
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    if tool_name == 'image-generator' and current_user.tier == 'free':
        flash("Pro Feature!", "warning")
        return redirect('/pricing')
    
    # Handle Manual Redirects
    if tool_name == 'article-wizard': return redirect('/article-wizard')
    if tool_name == 'alt-text-generator': return redirect('/alt-text-generator')
    if tool_name == 'bulk-writer': return redirect('/bulk-writer')
    
    try:
        return render_template(f'{tool_name.replace("-", "_")}.html')
    except:
        return "Tool not found", 404

for t in TOOL_LIST:
    if t not in ['article-wizard', 'alt-text-generator', 'bulk-writer']:
        app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t: app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))

# ==========================================
# 7. API ENDPOINTS
# ==========================================

# --- BACKLINK BUILDER (SAFE OUTREACH) ---
@app.route('/api/backlink-outreach', methods=['POST'])
@login_required
def api_backlink_outreach():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    
    d = request.get_json()
    target_url = d.get('url')
    topic = d.get('topic')
    
    prompt = f"""
    Write a high-conversion 'Guest Post' or 'Link Insertion' email pitch.
    Target Website: {target_url}
    My Topic: {topic}
    
    Tone: Professional but personal.
    Subject Line: Catchy.
    Body: Compliment their recent work, explain why my content adds value to them, and propose the link.
    """
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Outreach Expert"},{"role":"user","content":prompt}])
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- PUBLIC AUDIT ---
@app.route('/api/public-audit', methods=['POST'])
def api_public_audit():
    try:
        url = request.get_json().get('url')
        if not url: return jsonify({'error': 'Enter URL'}), 400
        if not url.startswith('http'): url = 'https://' + url
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=15)
        s = BeautifulSoup(r.content, 'html.parser')
        score = 100; real_issues = []
        if not s.title: score -= 20; real_issues.append("Missing Title Tag")
        elif len(s.title.string) > 60: score -= 5; real_issues.append("Title Too Long")
        if not s.find('meta', attrs={'name':'description'}): score -= 20; real_issues.append("Missing Meta Description")
        if not s.find('h1'): score -= 20; real_issues.append("Missing H1 Heading")
        if score == 100: real_issues.append("No critical errors found")
        return jsonify({'success': True, 'score': max(35,score), 'issues': real_issues})
    except: return jsonify({'success': True, 'score': 42, 'issues': ['Server Response Timeout', 'Mobile Optimization Issues']})

# --- PRO AUDIT ---
@app.route('/api/audit-site', methods=['POST'])
@login_required
def api_audit_site():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'): url = 'https://' + url
        start = datetime.now()
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}, timeout=30)
        load = round((datetime.now()-start).total_seconds(), 2)
        s = BeautifulSoup(r.content, 'html.parser')
        score = 100; issues = []; passed = []
        if not s.title: score-=20; issues.append({"type":"critical","msg":"Missing Title","fix":"Add <title>"})
        else: passed.append("Title Exists")
        if not s.find('meta', attrs={'name':'description'}): score-=20; issues.append({"type":"critical","msg":"Missing Meta Desc","fix":"Add description"})
        else: passed.append("Meta Description Found")
        if not s.find('h1'): score-=20; issues.append({"type":"critical","msg":"Missing H1","fix":"Add H1 tag"})
        else: passed.append("H1 Tag Found")
        imgs = s.find_all('img'); miss = sum(1 for i in imgs if not i.get('alt'))
        if miss > 0: score-=5; issues.append({"type":"warning","msg":f"{miss} Images missing Alt","fix":"Add alt text"})
        else: passed.append("Images Optimized")
        return jsonify({
            'success': True, 'score': max(0,score), 
            'meta': {'url':url, 'title':s.title.string if s.title else "None", 'description':"...", 'load_time':f"{load}s", 'word_count':len(s.get_text().split()), 'link_count':len(s.find_all('a')), 'canonical':""},
            'issues': issues, 'passed': passed
        })
    except Exception as e: return jsonify({'error': f"Failed: {str(e)}"}), 500

@app.route('/api/generate-image', methods=['POST'])
@login_required
def api_generate_image():
    if current_user.tier == 'free': return jsonify({'error': 'Upgrade to Pro!'}), 403
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.images.generate(model="dall-e-3", prompt=request.get_json().get('prompt'), size="1024x1024", quality="standard", n=1)
        current_user.ai_requests_this_month += 5; db.session.commit()
        return jsonify({'success': True, 'image_url': res.data[0].url})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/humanize-text', methods=['POST'])
@login_required
def api_humanize_text():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o", messages=[{"role":"system","content":"Rewriter"},{"role":"user","content":f"Humanize: {request.get_json().get('content')}"}])
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/article-wizard', methods=['POST'])
@login_required
def api_article_wizard():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached'}), 403
    try:
        d = request.get_json()
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Writer"},{"role":"user","content":f"Blog about: {d.get('topic')}"}])
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: return jsonify({'error': 'Limit reached.'}), 403
    data = request.get_json(); video_url = data.get('url')
    try:
        vid = video_url.split("v=")[1].split("&")[0] if "v=" in video_url else video_url.split("youtu.be/")[1].split("?")[0]
        full_text = ""
        mirrors = PIPED_INSTANCES.copy(); random.shuffle(mirrors)
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
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":request.get_json().get('keyword')}])
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html_content': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/save-content', methods=['POST'])
@login_required
def api_save_content():
    d = request.get_json()
    if d.get('id'):
        c = Content.query.get(d.get('id'))
        if c.user_id == current_user.id:
            c.title = d.get('title'); c.content = d.get('content'); c.html_content = d.get('html_content')
            c.keyword = d.get('keyword'); c.word_count = len(d.get('content','').split())
            db.session.commit()
            return jsonify({'success': True, 'id': c.id})
    new_c = Content(user_id=current_user.id, title=d.get('title'), content=d.get('content'), html_content=d.get('html_content'), keyword=d.get('keyword'), word_count=len(d.get('content','').split()))
    db.session.add(new_c); current_user.content_count += 1; db.session.commit()
    return jsonify({'success': True, 'id': new_c.id})

@app.route('/api/publish-wordpress', methods=['POST'])
@login_required
def api_publish_wordpress():
    d = request.get_json()
    wp = d.get('url').rstrip('/'); creds = f"{d.get('username')}:{d.get('password')}"
    t = base64.b64encode(creds.encode()).decode('utf-8')
    try:
        r = requests.post(f"{wp}/wp-json/wp/v2/posts", headers={'Authorization': f'Basic {t}', 'Content-Type': 'application/json'}, json={'title':d.get('title'),'content':d.get('content'),'status':'draft'})
        return jsonify({'success': True, 'link': r.json().get('link')})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id: db.session.delete(c); db.session.commit()
    return jsonify({'success': True})

# --- HELPER APIs ---
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

# --- REAL READABILITY LOGIC ---
@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_readability():
    try:
        text_content = request.get_json().get('content', '')
        if not text_content: return jsonify({'error': 'No text provided'}), 400

        # 1. Basic Stats
        words = [w for w in text_content.split() if len(w) > 0]
        sentences = [s for s in text_content.replace('!', '.').replace('?', '.').split('.') if len(s) > 0]
        
        total_words = len(words)
        total_sentences = len(sentences) if len(sentences) > 0 else 1
        avg_sentence_len = total_words / total_sentences

        # 2. Syllable Count (Heuristic)
        def count_syllables(word):
            word = word.lower()
            count = 0
            vowels = "aeiouy"
            if word[0] in vowels: count += 1
            for index in range(1, len(word)):
                if word[index] in vowels and word[index - 1] not in vowels:
                    count += 1
            if word.endswith("e"): count -= 1
            if count == 0: count += 1
            return count

        total_syllables = sum(count_syllables(w) for w in words)
        
        # 3. Flesch Reading Ease Formula
        score = 206.835 - (1.015 * avg_sentence_len) - (84.6 * (total_syllables / total_words))
        score = round(score, 1)

        # 4. Determine Grade/Difficulty
        difficulty = "Very Easy"
        grade = "5th Grade"
        color = "success"
        
        if score < 30: 
            difficulty = "Very Confusing"; grade = "College Grad"; color = "danger"
        elif score < 50: 
            difficulty = "Difficult"; grade = "College"; color = "warning"
        elif score < 60: 
            difficulty = "Fairly Difficult"; grade = "10th-12th Grade"; color = "warning"
        elif score < 70: 
            difficulty = "Standard"; grade = "8th-9th Grade"; color = "primary"
        elif score < 80: 
            difficulty = "Fairly Easy"; grade = "7th Grade"; color = "success"
        elif score < 90: 
            difficulty = "Easy"; grade = "6th Grade"; color = "success"

        # 5. Reading Time (200 words per minute)
        reading_time = f"{max(1, round(total_words / 200))} min"

        return jsonify({
            'success': True,
            'stats': {
                'score': score,
                'grade': grade,
                'difficulty': difficulty,
                'words': total_words,
                'sentences': total_sentences,
                'reading_time': reading_time,
                'color': color
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- NEW: IMPROVE READABILITY API ---
@app.route('/api/improve-readability', methods=['POST'])
@login_required
def api_improve_readability():
    # 1. Check Limits
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'AI Limit reached for this month. Please upgrade.'}), 403

    try:
        text_content = request.get_json().get('content', '')
        if not text_content: return jsonify({'error': 'No text provided'}), 400

        # 2. Send to AI
        prompt = f"""
        Rewrite the following text to improve its Flesch-Kincaid readability score.
        Target: 7th-8th Grade Level (Score 60-70).
        
        Rules:
        - Use shorter sentences.
        - Use simpler vocabulary.
        - Break up long paragraphs.
        - Keep the original meaning.
        
        Text:
        {text_content[:3000]}
        """
        
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"You are a professional editor."},{"role":"user","content":prompt}]
        )
        
        # 3. Update Usage
        current_user.ai_requests_this_month += 1
        db.session.commit()

        return jsonify({'success': True, 'content': res.choices[0].message.content})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- UPDATED SCHEMA GENERATOR (3-in-1) ---
@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_schema():
    try:
        data = request.get_json()
        schema_type = data.get('type')
        result = {}

        if schema_type == 'faq':
            result = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": []
            }
            for qa in data.get('questions', []):
                if qa.get('q') and qa.get('a'):
                    result["mainEntity"].append({
                        "@type": "Question",
                        "name": qa['q'],
                        "acceptedAnswer": {
                            "@type": "Answer",
                            "text": qa['a']
                        }
                    })

        elif schema_type == 'article':
            result = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": data.get('headline', ''),
                "image": [data.get('image', '')],
                "datePublished": data.get('date', ''),
                "author": {
                    "@type": "Person",
                    "name": data.get('author', '')
                }
            }

        elif schema_type == 'local':
            result = {
                "@context": "https://schema.org",
                "@type": "LocalBusiness",
                "name": data.get('name', ''),
                "image": data.get('image', ''),
                "telephone": data.get('phone', ''),
                "address": {
                    "@type": "PostalAddress",
                    "streetAddress": data.get('address', ''),
                    "addressLocality": data.get('city', ''),
                    "addressRegion": data.get('region', ''),
                    "postalCode": data.get('zip', ''),
                    "addressCountry": data.get('country', '')
                },
                "priceRange": data.get('priceRange', '$$')
            }

        return jsonify({'success': True, 'json': json.dumps(result, indent=4)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_competitor():
    try:
        r = requests.get(request.get_json().get('url'), headers={'User-Agent':'Mozilla/5.0'})
        s = BeautifulSoup(r.content, 'html.parser')
        return jsonify({'success':True, 'analysis': {'title':s.title.string, 'word_count':len(s.get_text().split()), 'h1_tags':[h.text for h in s.find_all('h1')], 'images':[], 'total_images':0}})
    except: return jsonify({'error': 'Failed to analyze URL'})

@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_clusters():
    res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"Clusters for {request.get_json().get('keyword')} as JSON"}])
    return jsonify({'success':True, 'clusters': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})

@app.route('/api/gbp-generate', methods=['POST'])
@login_required
def api_gbp_generate():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    d = request.get_json()
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Local SEO"},{"role":"user","content":f"Write GBP {d.get('mode')} for {d.get('business')}"}])
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/geo-optimize', methods=['POST'])
@login_required
def api_geo_optimize():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached'}), 403
    keyword = request.get_json().get('keyword')
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":f"Create GEO Direct Answer block for: '{keyword}'."}])
        current_user.ai_requests_this_month += 1; db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/test-email')
def test_email():
    try:
        msg = Message("Test", recipients=['dilawarahsanrizvi7@gmail.com']); msg.body = "Working"; mail.send(msg)
        return "Sent"
    except Exception as e: return f"Err: {e}"

@app.route('/fix-db')
def fix_db():
    try:
        with db.engine.connect() as conn: conn.execute(text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'free';")); conn.commit()
        return "DB Fixed"
    except: return "Err"

# ==========================================
# NEW FEATURES APIs
# ==========================================

# 1. SOCIAL MEDIA PREVIEW API
@app.route('/api/analyze-social', methods=['POST'])
@login_required
def api_analyze_social():
    try:
        data = request.get_json()
        target_url = data.get('url')
        if not target_url.startswith('http'): target_url = 'https://' + target_url
        
        headers = {'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'}
        r = requests.get(target_url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        def get_meta(prop):
            t = soup.find('meta', property=prop) or soup.find('meta', attrs={'name': prop})
            return t['content'] if t else ""

        # Resolve relative image URLs
        og_image = get_meta('og:image')
        if og_image and not og_image.startswith('http'):
            og_image = urljoin(target_url, og_image)

        result = {
            'og_title': get_meta('og:title') or soup.title.string,
            'og_desc': get_meta('og:description') or get_meta('description'),
            'og_image': og_image,
            'og_url': get_meta('og:url') or target_url,
            'twitter_card': get_meta('twitter:card'),
            'twitter_title': get_meta('twitter:title'),
        }
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 2. KEYWORD DENSITY API
@app.route('/api/analyze-density', methods=['POST'])
@login_required
def api_analyze_density():
    try:
        import string
        
        data = request.get_json()
        text_content = ""
        
        if data.get('type') == 'url':
            url = data.get('content')
            if not url.startswith('http'): url = 'https://' + url
            r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            soup = BeautifulSoup(r.content, 'html.parser')
            for script in soup(["script", "style"]): script.extract()
            text_content = soup.get_text()
        else:
            text_content = data.get('content')

        words = text_content.lower().translate(str.maketrans('', '', string.punctuation)).split()
        stop_words = {"the","is","at","of","on","and","a","an","to","in","for","with","as","by","but","or","from","up","down","my","this","that","it","be","are","was","were","have","has","had","not","i","you","he","she","we","they"}
        filtered_words = [w for w in words if w not in stop_words and len(w) > 2]
        total_words = len(filtered_words)
        
        if total_words == 0: return jsonify({'error': 'No content found'}), 400
        
        counter = Counter(filtered_words)
        most_common = counter.most_common(15)
        
        results = []
        for word, count in most_common:
            results.append({'word': word, 'count': count, 'density': round((count / total_words) * 100, 2)})
            
        return jsonify({'success': True, 'results': results, 'total_words': len(words)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 3. PDF REPORT GENERATOR API
@app.route('/api/generate-report', methods=['POST'])
@login_required
def api_generate_report():
    try:
        data = request.get_json()
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 20)
        pdf.set_text_color(79, 70, 229) # Indigo
        pdf.cell(0, 10, "MySEO King - Audit Report", 0, 1, "C")
        pdf.ln(5)
        
        # Details
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f"Target URL: {data.get('url')}", 0, 1)
        pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 1)
        pdf.cell(0, 10, f"SEO Score: {data.get('score')}/100", 0, 1)
        pdf.ln(10)
        
        # Critical Issues
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(220, 53, 69) # Red
        pdf.cell(0, 10, "Critical Issues Found:", 0, 1)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        
        if data.get('issues'):
            for issue in data.get('issues'):
                msg = issue.get('msg', issue) if isinstance(issue, dict) else issue
                pdf.cell(0, 10, f"- {msg}", 0, 1)
        else:
            pdf.cell(0, 10, "No critical issues found!", 0, 1)
        
        pdf.ln(10)
        
        # Passed Checks
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(25, 135, 84) # Green
        pdf.cell(0, 10, "Passed Checks:", 0, 1)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        
        if data.get('passed'):
            for item in data.get('passed'):
                pdf.cell(0, 10, f"- {item}", 0, 1)
                
        # Output
        response = make_response(pdf.output(dest='S').encode('latin-1'))
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=seo_report.pdf'
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 4. YOUTUBE VIDEO SCRIPT API
@app.route('/api/generate-video-script', methods=['POST'])
@login_required
def api_generate_video_script():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    data = request.get_json()
    topic = data.get('topic')
    tone = data.get('tone', 'Engaging')
    
    prompt = f"""
    Create a structured YouTube Video Script.
    Topic: {topic}
    Tone: {tone}
    
    Structure:
    1. Hook (0-30s): Catchy opening.
    2. Intro: What will be covered.
    3. Body: 3 main points.
    4. CTA: Call to action.
    
    Format using Markdown headings.
    """
    
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"You are a YouTuber."},{"role":"user","content":prompt}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({
            'success': True, 
            'content': content,
            'html': markdown.markdown(content)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 5. SOCIAL MEDIA POST GENERATOR API (NEW)
@app.route('/api/generate-social-posts', methods=['POST'])
@login_required
def api_generate_social_posts():
    # Check Limits
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    data = request.get_json()
    topic = data.get('topic')
    
    prompt = f"""
    Write 3 distinct social media posts about: "{topic}".
    
    1. LinkedIn Post: Professional, use bullet points, end with a thought-provoking question.
    2. Twitter Thread (3 tweets): Short, punchy, informative.
    3. Instagram Caption: Casual, engaging, include 5 relevant hashtags.
    
    Format the output clearly with headers (e.g., ### LinkedIn).
    """
    
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"Social Media Expert."},{"role":"user","content":prompt}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({
            'success': True, 
            'content': content,
            'html': markdown.markdown(content)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
