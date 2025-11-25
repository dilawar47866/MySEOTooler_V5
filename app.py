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
# 1. CONFIG & SAFE IMPORTS
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
# 3. HELPERS
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
# 4. ROUTES & VIEWS
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

# Template Routes
@app.route('/profile')
@login_required
def profile(): return render_template('profile.html', user=current_user, limits=current_user.get_limits())
@app.route('/pricing')
def pricing(): return render_template('pricing.html')
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
# 5. API - CORE FUNCTIONS
# ============================================================================

# --- 1. AI GENERATOR WITH HUMANIZER MODE ---
@app.route('/api/generate-content', methods=['POST'])
@api_login_required
def api_generate_content():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    try:
        data = request.get_json()
        keyword = data.get('keyword', '')
        mode = data.get('mode', 'standard')
        
        # HUMANIZER LOGIC
        if mode == 'human':
            system = """You are a highly opinionated, expert human writer. 
            Your goal is to bypass AI detection by using high burstiness and perplexity.
            1. Do NOT use words like 'However', 'Furthermore', 'In conclusion'.
            2. Vary sentence length drastically. Use fragments. Use run-ons.
            3. Be conversational, maybe even a bit controversial.
            4. Write from personal experience."""
            temp = 0.85
        else:
            system = "You are an SEO expert. Write a comprehensive, structured article using Markdown H2/H3."
            temp = 0.7

        prompt = f"Write a {mode} style article about: {keyword}. Minimum 1000 words."
        result = call_openai(prompt, 2000, system_prompt=system, temperature=temp)
        
        if 'error' in result: return jsonify(result), 500
        
        # Calculate Score & Save
        html = markdown.markdown(result['content'])
        score = 0
        if len(result['content'].split()) > 500: score += 50
        if keyword.lower() in 
