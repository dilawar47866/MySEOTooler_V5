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
from bs4 import BeautifulSoup
from urllib.parse import urlparse
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
# 1. SAFE NLTK IMPORT (PREVENTS RAILWAY CRASHES)
# ============================================================================
try:
    import nltk
    from nltk.tokenize import word_tokenize, sent_tokenize
    # Force download path to /tmp (writable in serverless envs)
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
    """Safe sentence tokenization with fallback"""
    if NLTK_AVAILABLE:
        try: return sent_tokenize(text)
        except: pass
    # Fallback
    return [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]

def safe_word_tokenize(text):
    """Safe word tokenization with fallback"""
    if NLTK_AVAILABLE:
        try: return word_tokenize(text)
        except: pass
    # Fallback
    return text.split()

# ============================================================================
# 2. CONFIGURATION
# ============================================================================
load_dotenv()
app = Flask(__name__)

# Database
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///myseotoolver5.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'myseotoolver5-secret-2024')

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# OpenAI
openai_api_key = os.getenv('OPENAI_API_KEY')
client = OpenAI(api_key=openai_api_key) if openai_api_key else None

# ============================================================================
# 3. MODELS
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
            self.content_count = 0
            self.ai_requests_this_month = 0
            self.last_reset_date = now
            db.session.commit()

    def get_limits(self):
        limits = {
            'free': {'content_per_month': 5, 'ai_requests_per_month': 50, 'export_formats': ['txt', 'html']},
            'pro': {'content_per_month': 50, 'ai_requests_per_month': 500, 'export_formats': ['txt', 'html', 'md', 'docx']},
            'enterprise': {'content_per_month': 999999, 'ai_requests_per_month': 999999, 'export_formats': ['txt', 'html', 'md', 'docx']}
        }
        return limits.get(self.tier, limits['free'])

    def can_create_content(self):
        self.reset_monthly_limits()
        return self.content_count < self.get_limits()['content_per_month']

    def can_use_ai(self):
        self.reset_monthly_limits()
        return self.ai_requests_this_month < self.get_limits()['ai_requests_per_month']

    def increment_ai_usage(self):
        self.ai_requests_this_month += 1
        db.session.commit()

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
    content_type = db.Column(db.String(50), default='article')
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'keyword': self.keyword,
            'content': self.content,
            'html_content': self.html_content,
            'seo_score': self.seo_score,
            'word_count': self.word_count,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else '',
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else '',
            'content_type': self.content_type
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================================================
# 4. HELPER FUNCTIONS
# ============================================================================
def call_openai(prompt, max_tokens=1000):
    if not client:
        return {"error": "OpenAI API key not configured."}
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are an expert SEO content strategist."}, 
                      {"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.7
        )
        return {"success": True, "content": response.choices[0].message.content}
    except Exception as e:
        return {"error": f"OpenAI API Error: {str(e)}"}

def calculate_seo_score(content, keyword):
    if not content: return 0
    score = 0
    content_lower = content.lower()
    keyword_lower = keyword.lower() if keyword else ""
    word_count = len(content.split())
    
    if word_count >= 300: score += 30
    elif word_count >= 150: score += 15
    
    if keyword_lower and keyword_lower in content_lower:
        k_count = content_lower.count(keyword_lower)
        if k_count >= 3: score += 30
        else: score += 15
    
    if re.search(r'#+\s', content): score += 20
    if word_count >= 1000: score += 20
    elif word_count >= 500: score += 10
    return min(score, 100)

def get_seo_grade(score):
    if score >= 90: return 'A+'
    elif score >= 80: return 'A'
    elif score >= 70: return 'B'
    elif score >= 60: return 'C'
    elif score >= 50: return 'D'
    else: return 'F'

def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# 5. PAGE ROUTES (LANDING + DASHBOARD + TOOLS)
# ============================================================================

@app.route('/')
def landing():
    """NEW Landing Page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main Dashboard (Formerly Index)"""
    current_user.reset_monthly_limits()
    total_content = Content.query.filter_by(user_id=current_user.id).count()
    total_words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    avg_score = db.session.query(db.func.avg(Content.seo_score)).filter_by(user_id=current_user.id).scalar() or 0
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()

    return render_template('index.html',
                         total_content=total_content,
                         total_words=total_words,
                         avg_score=round(avg_score, 1),
                         recent_content=recent,
                         limits=current_user.get_limits())

@app.route('/index')
@login_required
def index():
    return redirect(url_for('dashboard'))

# Auth Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
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
def profile():
    return render_template('profile.html', user=current_user, limits=current_user.get_limits())

@app.route('/pricing')
def pricing(): return render_template('pricing.html')

# Tool Page Routes (Rendering HTML Templates)
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
    if request.args.get('id'):
        content = Content.query.filter_by(id=request.args.get('id'), user_id=current_user.id).first()
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
# 6. ALL API ROUTES (RESTORED FULLY)
# ============================================================================

@app.route('/api/generate-keywords', methods=['POST'])
@api_login_required
def api_generate_keywords():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        seed = data.get('keyword', '').strip()
        prompt = f"Generate 15 SEO keyword variations for '{seed}'. Format as list."
        result = call_openai(prompt, 500)
        if "error" in result: return jsonify({'error': result['error']}), 500
        keywords = [line.strip().lstrip('-•*0123456789. ') for line in result['content'].split('\n') if line.strip()][:15]
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'keywords': keywords})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/serp-analysis', methods=['POST'])
@api_login_required
def api_serp_analysis():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        prompt = f"Analyze SERP for: '{keyword}'. Provide: Search Volume (est), Difficulty (0-100), Intent, and 3 Content Recommendations."
        result = call_openai(prompt, 800)
        if "error" in result: return jsonify({'error': result['error']}), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'data': {'analysis': result['content']}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@api_login_required
def api_generate_content():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '')
        prompt = f"Write SEO article about {keyword}. Use markdown H2/H3. Min 1000 words."
        result = call_openai(prompt, 2000)
        if 'error' in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'content': result['content'], 'html_content': markdown.markdown(result['content'])})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/save-content', methods=['POST'])
@api_login_required
def api_save_content():
    try:
        data = request.get_json()
        if data.get('id'):
            c = Content.query.filter_by(id=data.get('id'), user_id=current_user.id).first()
            if c:
                c.content = data.get('content')
                c.title = data.get('title')
                c.keyword = data.get('keyword')
                c.updated_at = datetime.utcnow()
                db.session.commit()
                return jsonify({'success': True, 'id': c.id})
        if not current_user.can_create_content(): return jsonify({'error': 'Limit reached'}), 403
        c = Content(user_id=current_user.id, title=data.get('title'), content=data.get('content'), keyword=data.get('keyword'))
        db.session.add(c)
        current_user.content_count += 1
        db.session.commit()
        return jsonify({'success': True, 'id': c.id})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/check-readability', methods=['POST'])
@api_login_required
def api_check_readability():
    try:
        data = request.get_json()
        content = data.get('content', '')
        if not content: return jsonify({'error': 'Content required'}), 400
        score = textstat.flesch_reading_ease(content)
        grade = textstat.flesch_kincaid_grade(content)
        return jsonify({
            'success': True, 'flesch_score': round(score, 1),
            'grade_level': round(grade, 1), 'word_count': len(content.split())
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-headline', methods=['POST'])
@api_login_required
def api_analyze_headline():
    try:
        data = request.get_json()
        headline = data.get('headline', '').strip()
        if not headline: return jsonify({'error': 'Headline required'}), 400
        
        # Basic logic for demonstration
        char_count = len(headline)
        word_count = len(headline.split())
        score = 50
        if 40 <= char_count <= 60: score += 20
        if '?' in headline or headline[0].isdigit(): score += 15
        
        return jsonify({
            'success': True, 'headline': headline,
            'overall_score': min(score, 100), 'char_count': char_count
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-lsi-keywords', methods=['POST'])
@api_login_required
def api_generate_lsi_keywords():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '')
        result = call_openai(f"Generate 20 LSI keywords for '{keyword}'", 500)
        if "error" in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        # Parse list
        keywords = [line.strip().lstrip('- ') for line in result['content'].split('\n') if line.strip()][:20]
        return jsonify({'success': True, 'keywords': keywords})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content-brief', methods=['POST'])
@api_login_required
def api_generate_content_brief():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '')
        result = call_openai(f"Create content brief for '{keyword}'. Include audience, intent, outline.", 1000)
        if "error" in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'brief': result['content']})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-outline', methods=['POST'])
@api_login_required
def api_generate_outline():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        topic = data.get('topic', '')
        result = call_openai(f"Create article outline for '{topic}' with H2 and H3 tags.", 1000)
        if "error" in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'outline': result['content']})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/check-plagiarism', methods=['POST'])
@api_login_required
def api_check_plagiarism():
    try:
        data = request.get_json()
        content = data.get('content', '')
        if not content: return jsonify({'error': 'No content'}), 400
        
        # Check against user's own database content
        all_content = Content.query.filter_by(user_id=current_user.id).all()
        matches = []
        sentences = safe_sent_tokenize(content)
        
        for existing in all_content:
            if not existing.content: continue
            ex_sentences = safe_sent_tokenize(existing.content)
            common = set(sentences).intersection(set(ex_sentences))
            if common:
                matches.append({'source_title': existing.title, 'count': len(common)})
        
        verdict = "High Similarity" if matches else "Original"
        return jsonify({'success': True, 'verdict': verdict, 'matches': matches})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/optimize-image-seo', methods=['POST'])
@api_login_required
def api_optimize_image_seo():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        images = data.get('images', []) # List of descriptions
        keyword = data.get('keyword', '')
        
        results = []
        for img_desc in images:
            prompt = f"Generate SEO Alt text and Filename for image: '{img_desc}' targeting '{keyword}'"
            res = call_openai(prompt, 200)
            if "error" not in res:
                results.append({'description': img_desc, 'result': res['content']})
                current_user.increment_ai_usage()
        
        return jsonify({'success': True, 'results': results})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-faq-schema', methods=['POST'])
@api_login_required
def api_generate_faq_schema():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        topic = data.get('topic', '')
        prompt = f"Generate 5 FAQs about '{topic}'. Format: Q: question A: answer"
        result = call_openai(prompt, 800)
        if "error" in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'qa_pairs': [], 'schema': result['content']}) # Simplified for safety
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-social-posts', methods=['POST'])
@api_login_required
def api_generate_social_posts():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        content = data.get('content', '')
        prompt = f"Write LinkedIn, Twitter, and Facebook posts for this content: {content[:500]}"
        result = call_openai(prompt, 800)
        if "error" in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'posts': {'generated': result['content']}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-competitor', methods=['POST'])
@api_login_required
def api_analyze_competitor():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.content, 'html.parser')
        
        return jsonify({
            'success': True,
            'analysis': {
                'title': soup.title.string if soup.title else 'No title',
                'h1_tags': [h.text.strip() for h in soup.find_all('h1')],
                'word_count': len(soup.get_text().split()),
                'image_count': len(soup.find_all('img'))
            }
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-robots', methods=['POST'])
@api_login_required
def api_generate_robots():
    try:
        data = request.get_json()
        txt = "User-agent: *\nAllow: /"
        if data.get('sitemap_url'): txt += f"\nSitemap: {data['sitemap_url']}"
        return jsonify({'success': True, 'robots_txt': txt})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-sitemap', methods=['POST'])
@api_login_required
def api_generate_sitemap():
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for u in urls: xml += f'<url><loc>{u["url"]}</loc></url>\n'
        xml += '</urlset>'
        return jsonify({'success': True, 'sitemap_xml': xml})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-youtube-script', methods=['POST'])
@api_login_required
def api_generate_youtube_script():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        topic = data.get('topic', '')
        result = call_openai(f"Write YouTube script for '{topic}'. Include Hook, Intro, Body, Outro.", 1000)
        if "error" in result: return jsonify(result), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'script': result['content']})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/test-subject-line', methods=['POST'])
@api_login_required
def api_test_subject_line():
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        score = 50
        if len(subject) < 60: score += 10
        if '?' in subject: score += 10
        return jsonify({'success': True, 'score': score, 'grade': 'B'})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-schema', methods=['POST'])
@api_login_required
def api_generate_schema():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        title = data.get('title', '')
        type_ = data.get('type', 'Article')
        schema = {
            "@context": "https://schema.org",
            "@type": type_,
            "headline": title,
            "datePublished": datetime.utcnow().strftime('%Y-%m-%d')
        }
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'schema': json.dumps(schema, indent=2)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-meta-tags', methods=['POST'])
@api_login_required
def api_generate_meta_tags():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        title = data.get('title', '')
        res = call_openai(f"Write meta description for '{title}'", 200)
        if "error" in res: return jsonify(res), 500
        current_user.increment_ai_usage()
        return jsonify({
            'success': True, 
            'meta_tags': {'title': title, 'description': res['content']},
            'html': f'<meta name="description" content="{res["content"]}">'
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-alt-text', methods=['POST'])
@api_login_required
def api_generate_alt_text():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        context = data.get('context', '')
        res = call_openai(f"Write alt text for image showing: {context}", 100)
        if "error" in res: return jsonify(res), 500
        current_user.increment_ai_usage()
        return jsonify({'success': True, 'alt_text': res['content']})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/suggest-internal-links', methods=['POST'])
@api_login_required
def api_suggest_internal_links():
    try:
        data = request.get_json()
        # Simple logic: suggest random recent posts
        recent = Content.query.filter_by(user_id=current_user.id).limit(5).all()
        suggestions = [{'title': c.title, 'id': c.id} for c in recent]
        return jsonify({'success': True, 'suggestions': suggestions})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/export/<int:content_id>/<format>')
@api_login_required
def api_export(content_id, format):
    try:
        content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
        if not content: return jsonify({'error': 'Content not found'}), 404
        
        if format == 'txt':
            output = BytesIO(f"{content.title}\n\n{content.content}".encode('utf-8'))
            return send_file(output, mimetype='text/plain', as_attachment=True, download_name=f"{content.title}.txt")
        # Add other formats if needed or use frontend to handle
        return jsonify({'error': 'Format not supported in this version'}), 400
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/health')
def health(): return jsonify({'status': 'healthy'})

# ============================================================================
# 7. INIT & RUN
# ============================================================================
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
