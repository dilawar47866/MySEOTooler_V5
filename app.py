from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import re
import os
import requests
import base64
from bs4 import BeautifulSoup
# CHANGED: Added urljoin to fix image paths
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from docx import Document
from io import BytesIO
import json
import textstat
import validators
from functools import wraps

# ============================================================================
# 1. SAFE IMPORTS & CONFIG
# ============================================================================
try:
    import nltk
    from nltk.tokenize import word_tokenize, sent_tokenize
    nltk.data.path.append('/tmp')
    try:
        nltk.download('punkt', download_dir='/tmp', quiet=True)
        nltk.download('stopwords', download_dir='/tmp', quiet=True)
        NLTK_AVAILABLE = True
    except Exception:
        NLTK_AVAILABLE = False
except ImportError:
    NLTK_AVAILABLE = False

def safe_sent_tokenize(text):
    if NLTK_AVAILABLE:
        try: return sent_tokenize(text)
        except: pass
    return [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]

def safe_word_tokenize(text):
    if NLTK_AVAILABLE:
        try: return word_tokenize(text)
        except: pass
    return text.split()

load_dotenv()
app = Flask(__name__)

# Database Config
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///myseotoolver5.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'myseotoolver5-secret-2024')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(app=app, key_func=get_remote_address, storage_uri="memory://")
openai_api_key = os.getenv('OPENAI_API_KEY')
client = OpenAI(api_key=openai_api_key) if openai_api_key else None

# ============================================================================
# 2. MODELS
# ============================================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tier = db.Column(db.String(20), default='free')
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    content_count = db.Column(db.Integer, default=0)
    ai_requests_this_month = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
    contents = db.relationship('Content', backref='author', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    def reset_monthly_limits(self):
        now = datetime.utcnow()
        if self.last_reset_date is None or self.last_reset_date.month != now.month:
            self.content_count = 0; self.ai_requests_this_month = 0; self.last_reset_date = now
            db.session.commit()
    def get_limits(self):
        limits = {
            'free': {'content_per_month': 5, 'ai_requests_per_month': 50, 'export_formats': ['txt', 'html']},
            'pro': {'content_per_month': 50, 'ai_requests_per_month': 500, 'export_formats': ['txt', 'html', 'md', 'docx']},
            'enterprise': {'content_per_month': 999999, 'ai_requests_per_month': 999999, 'export_formats': ['txt', 'html', 'md', 'docx']}
        }
        return limits.get(self.tier, limits['free'])
    def can_create_content(self):
        self.reset_monthly_limits(); return self.content_count < self.get_limits()['content_per_month']
    def can_use_ai(self):
        self.reset_monthly_limits(); return self.ai_requests_this_month < self.get_limits()['ai_requests_per_month']
    def increment_ai_usage(self):
        self.ai_requests_this_month += 1; db.session.commit()

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    keyword = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    html_content = db.Column(db.Text)
    seo_score = db.Column(db.Integer, default=0)
    word_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {'id': self.id, 'title': self.title, 'keyword': self.keyword, 'content': self.content, 
                'html_content': self.html_content, 'seo_score': self.seo_score, 'word_count': self.word_count, 
                'created_at': self.created_at.strftime('%Y-%m-%d')}

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# ============================================================================
# 3. HELPER FUNCTIONS
# ============================================================================
def call_openai(prompt, max_tokens=1000, system_prompt="You are an SEO expert.", temperature=0.7):
    if not client: return {"error": "OpenAI API key not configured."}
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}],
            max_tokens=max_tokens, temperature=temperature
        )
        return {"success": True, "content": response.choices[0].message.content}
    except Exception as e: return {"error": str(e)}

def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated: return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# 4. CORE ROUTES (Landing, Auth, Dashboard)
# ============================================================================
@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    current_user.reset_monthly_limits()
    total_content = Content.query.filter_by(user_id=current_user.id).count()
    total_words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    avg_score = db.session.query(db.func.avg(Content.seo_score)).filter_by(user_id=current_user.id).scalar() or 0
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
    return render_template('index.html', total_content=total_content, total_words=total_words, 
                         avg_score=round(avg_score, 1), recent_content=recent, limits=current_user.get_limits())

@app.route('/index')
@login_required
def index(): return redirect(url_for('dashboard'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            if User.query.filter_by(email=data.get('email').lower()).first(): return jsonify({'error': 'Email taken'}), 400
            user = User(username=data.get('username'), email=data.get('email').lower())
            user.set_password(data.get('password'))
            if User.query.count() == 0: user.is_admin = True
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        except Exception as e: return jsonify({'error': str(e)}), 500
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        if user and user.check_password(data.get('password')):
            login_user(user)
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))

@app.route('/profile')
@login_required
def profile(): return render_template('profile.html', user=current_user, limits=current_user.get_limits())

@app.route('/pricing')
def pricing(): return render_template('pricing.html')

# ============================================================================
# 5. ADMIN ROUTES
# ============================================================================
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin.html', users=users, total_users=len(users), total_content=Content.query.count())

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not current_user.is_admin: return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: return jsonify({'error': 'Cannot ban yourself'}), 400
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True, 'status': user.is_active})

@app.route('/admin/user/<int:user_id>/tier', methods=['POST'])
@login_required
def admin_change_tier(user_id):
    if not current_user.is_admin: return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if data.get('tier') in ['free', 'pro', 'enterprise']:
        user.tier = data.get('tier')
        db.session.commit()
        return jsonify({'success': True, 'tier': user.tier})
    return jsonify({'error': 'Invalid tier'}), 400

# ============================================================================
# 6. TOOL TEMPLATE ROUTES
# ============================================================================
@app.route('/keyword-research')
@login_required
def keyword_research(): return render_template('keyword_research.html')
@app.route('/serp-analysis')
@login_required
def serp_analysis(): return render_template('serp_analysis.html')
@app.route('/content-generator')
@login_required
def content_generator(): return render_template('content_generator.html')
@app.route('/content-library')
@login_required
def content_library():
    contents = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).all()
    return render_template('content_library.html', contents=contents)
@app.route('/editor')
@login_required
def editor():
    content = None
    if request.args.get('id'): content = Content.query.filter_by(id=request.args.get('id'), user_id=current_user.id).first()
    return render_template('editor.html', content=content)
@app.route('/schema-generator')
@login_required
def schema_generator(): return render_template('schema_generator.html')
@app.route('/meta-tags')
@login_required
def meta_tags(): return render_template('meta_tags.html')
@app.route('/alt-text-generator')
@login_required
def alt_text_generator(): return render_template('alt_text.html')
@app.route('/readability-checker')
@login_required
def readability_checker(): return render_template('readability_checker.html')
@app.route('/headline-analyzer')
@login_required
def headline_analyzer(): return render_template('headline_analyzer.html')
@app.route('/lsi-keywords')
@login_required
def lsi_keywords(): return render_template('lsi_keywords.html')
@app.route('/content-brief')
@login_required
def content_brief(): return render_template('content_brief.html')
@app.route('/internal-linking')
@login_required
def internal_linking(): return render_template('internal_linking.html')
@app.route('/content-outline')
@login_required
def content_outline(): return render_template('content_outline.html')
@app.route('/plagiarism-checker')
@login_required
def plagiarism_checker(): return render_template('plagiarism_checker.html')
@app.route('/image-seo')
@login_required
def image_seo(): return render_template('image_seo.html')
@app.route('/faq-schema')
@login_required
def faq_schema(): return render_template('faq_schema.html')
@app.route('/social-posts')
@login_required
def social_posts(): return render_template('social_posts.html')
@app.route('/competitor-analyzer')
@login_required
def competitor_analyzer(): return render_template('competitor_analyzer.html')
@app.route('/robots-generator')
@login_required
def robots_generator(): return render_template('robots_generator.html')
@app.route('/sitemap-generator')
@login_required
def sitemap_generator(): return render_template('sitemap_generator.html')
@app.route('/youtube-script')
@login_required
def youtube_script(): return render_template('youtube_script.html')
@app.route('/email-subject')
@login_required
def email_subject(): return render_template('email_subject.html')

# ============================================================================
# 7. API ENDPOINTS
# ============================================================================

# Humanizer / AI Writer
@app.route('/api/generate-content', methods=['POST'])
@api_login_required
def api_generate_content():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '')
        mode = data.get('mode', 'standard')
        
        if mode == 'human':
            system = "You are a highly opinionated human writer. Use high burstiness and perplexity. Do NOT use AI transition words like 'However'. Write with personality."
            temp = 0.85
        else:
            system = "You are an SEO expert. Write a comprehensive article using Markdown H2/H3."
            temp = 0.7

        prompt = f"Write a {mode} style article about: {keyword}. Minimum 1000 words."
        result = call_openai(prompt, 2000, system_prompt=system, temperature=temp)
        
        if 'error' in result: return jsonify(result), 500
        
        html = markdown.markdown(result['content'])
        score = 0
        if len(result['content'].split()) > 500: score += 50
        if keyword.lower() in result['content'].lower(): score += 30
        
        c = Content(user_id=current_user.id, title=f"{keyword} ({mode.title()})", 
                   content=result['content'], html_content=html, keyword=keyword,
                   word_count=len(result['content'].split()), seo_score=min(score, 100))
        db.session.add(c)
        current_user.increment_ai_usage()
        current_user.content_count += 1
        db.session.commit()

        return jsonify({'success': True, 'content': result['content'], 'html_content': html, 'id': c.id})
    except Exception as e: return jsonify({'error': str(e)}), 500

# WordPress
@app.route('/api/publish-wordpress', methods=['POST'])
@api_login_required
def api_publish_wordpress():
    try:
        data = request.get_json()
        wp_url, wp_user, wp_pass = data.get('url'), data.get('user'), data.get('password')
        title, content = data.get('title'), data.get('content')
        
        if not all([wp_url, wp_user, wp_pass]): return jsonify({'error': 'Missing credentials'}), 400
        
        creds = f"{wp_user}:{wp_pass}"
        token = base64.b64encode(creds.encode()).decode('utf-8')
        
        endpoint = f"{wp_url.rstrip('/')}/wp-json/wp/v2/posts"
        headers = {'Authorization': f'Basic {token}', 'Content-Type': 'application/json'}
        payload = {'title': title, 'content': content, 'status': 'draft'}
        
        r = requests.post(endpoint, headers=headers, json=payload)
        if r.status_code == 201: return jsonify({'success': True, 'link': r.json().get('link')})
        return jsonify({'error': f"WP Error: {r.text}"}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

# General Tools
@app.route('/api/generate-keywords', methods=['POST'])
@api_login_required
def api_generate_keywords():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        res = call_openai(f"Generate 15 SEO keywords for '{data.get('keyword')}'", 500)
        if 'error' in res: return jsonify(res), 500
        kws = [l.strip().lstrip('- 123.') for l in res['content'].split('\n') if l.strip()][:15]
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'keywords': kws})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/serp-analysis', methods=['POST'])
@api_login_required
def api_serp_analysis():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        res = call_openai(f"Analyze SERP for '{request.get_json().get('keyword')}'. Include difficulty & intent.", 800)
        if 'error' in res: return jsonify(res), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'data': {'analysis': res['content']}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-social-posts', methods=['POST'])
@api_login_required
def api_generate_social_posts():
    try:
        res = call_openai(f"Write social posts for: {request.get_json().get('content')[:500]}", 800)
        return jsonify({'success': True, 'posts': {'generated': res['content']}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/check-plagiarism', methods=['POST'])
@api_login_required
def api_check_plagiarism():
    try:
        content = request.get_json().get('content', '')
        all_c = Content.query.filter_by(user_id=current_user.id).all()
        sents = safe_sent_tokenize(content)
        matches = []
        for c in all_c:
            if not c.content: continue
            common = set(sents).intersection(set(safe_sent_tokenize(c.content)))
            if common: matches.append({'source_title': c.title, 'count': len(common)})
        return jsonify({'success': True, 'verdict': 'High Similarity' if matches else 'Original', 'matches': matches})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- UPDATED COMPETITOR ANALYSIS (Fixes Not Acceptable & Undefined Images) ---
@app.route('/api/analyze-competitor', methods=['POST'])
@api_login_required
def api_analyze_competitor():
    try:
        url = request.get_json().get('url', '')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        
        # Added Headers to fix 406 Not Acceptable
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 406:
            return jsonify({'error': 'Target site blocked the request (406).'}), 406
            
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Fix for "undefined" images
        images = []
        for img in soup.find_all('img'):
            src = img.get('src')
            if src:
                full_src = urljoin(url, src)
                images.append({'src': full_src, 'alt': img.get('alt', '')})
        
        # Clean text extraction for score calculations
        for script in soup(["script", "style"]):
            script.extract()
        
        return jsonify({
            'success': True, 
            'analysis': {
                'title': soup.title.string if soup.title else "No Title", 
                'word_count': len(soup.get_text().split()), 
                'h1_tags': [h.text.strip() for h in soup.find_all('h1')],
                'images': images,
                'total_images': len(images)
            }
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- NEW ROBOTS GENERATOR API ---
@app.route('/api/generate-robots', methods=['POST'])
@api_login_required
def api_generate_robots():
    try:
        data = request.get_json()
        content = f"User-agent: {data.get('userAgent', '*')}\n"
        if data.get('allow'): content += f"Allow: {data.get('allow')}\n"
        if data.get('disallow'): content += f"Disallow: {data.get('disallow')}\n"
        if data.get('sitemap'): content += f"\nSitemap: {data.get('sitemap')}"
        return jsonify({'success': True, 'content': content})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- NEW SITEMAP GENERATOR API ---
@app.route('/api/generate-sitemap', methods=['POST'])
@api_login_required
def api_generate_sitemap():
    try:
        url = request.get_json().get('url', '')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        links = set([url.rstrip('/')])
        
        for a in soup.find_all('a', href=True):
            full_url = urljoin(base_url, a['href'])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                links.add(full_url.split('#')[0].split('?')[0])
        
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for link in list(links)[:50]:
            xml += f'  <url>\n    <loc>{link}</loc>\n    <changefreq>weekly</changefreq>\n  </url>\n'
        xml += '</urlset>'
        return jsonify({'success': True, 'sitemap': xml})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-schema', methods=['POST'])
@api_login_required
def api_generate_schema():
    d = request.get_json()
    return jsonify({'success': True, 'schema': json.dumps({"@context": "https://schema.org", "@type": d.get('type'), "headline": d.get('title')}, indent=2)})

@app.route('/api/generate-meta-tags', methods=['POST'])
@api_login_required
def api_generate_meta_tags():
    res = call_openai(f"Write meta desc for {request.get_json().get('title')}", 200)
    return jsonify({'success': True, 'meta_tags': {'title': request.get_json().get('title'), 'description': res['content']}})

@app.route('/api/generate-youtube-script', methods=['POST'])
@api_login_required
def api_generate_youtube_script():
    res = call_openai(f"YouTube script for {request.get_json().get('topic')}", 1000)
    return jsonify({'success': True, 'script': res['content']})

@app.route('/api/save-content', methods=['POST'])
@api_login_required
def api_save_content():
    d = request.get_json()
    content_id = d.get('id')
    
    # 1. UPDATE EXISTING CONTENT
    if content_id:
        c = Content.query.get(content_id)
        if c and c.user_id == current_user.id:
            c.title = d.get('title')
            c.keyword = d.get('keyword')
            c.content = d.get('content') # Plain text
            c.html_content = d.get('html_content') # Full HTML
            c.word_count = len(d.get('content', '').split())
            # Simple score recalc
            c.updated_at = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True, 'id': c.id})
    
    # 2. CREATE NEW CONTENT (If ID is missing)
    try:
        new_c = Content(
            user_id=current_user.id,
            title=d.get('title', 'Untitled Draft'),
            keyword=d.get('keyword', ''),
            content=d.get('content', ''),
            html_content=d.get('html_content', ''),
            word_count=len(d.get('content', '').split()),
            seo_score=0
        )
        db.session.add(new_c)
        current_user.content_count += 1
        db.session.commit()
        return jsonify({'success': True, 'id': new_c.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ============================================================================
# 8. INIT & RUN
# ============================================================================

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

# This ensures tables exist when Gunicorn starts
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"DB Warning: {e}")

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
