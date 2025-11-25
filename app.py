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

# --- NLTK SAFE IMPORT ---
# This prevents the app from crashing if NLTK data cannot be downloaded on Railway
try:
    import nltk
    from nltk.tokenize import word_tokenize, sent_tokenize
    # Attempt to set a writable path for NLTK data
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
        try:
            return sent_tokenize(text)
        except:
            pass
    return [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]

def safe_word_tokenize(text):
    if NLTK_AVAILABLE:
        try:
            return word_tokenize(text)
        except:
            pass
    return text.split()

# Load environment
load_dotenv()

app = Flask(__name__)

# Database Configuration
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

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# OpenAI
openai_api_key = os.getenv('OPENAI_API_KEY')
client = OpenAI(api_key=openai_api_key) if openai_api_key else None

# --- MODELS ---
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
    
    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'keyword': self.keyword,
            'content': self.content, 'word_count': self.word_count,
            'created_at': self.created_at.strftime('%Y-%m-%d')
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- HELPERS ---
def call_openai(prompt, max_tokens=1000):
    if not client:
        return {"error": "OpenAI API key not configured."}
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are an SEO expert."}, 
                      {"role": "user", "content": prompt}],
            max_tokens=max_tokens, temperature=0.7
        )
        return {"success": True, "content": response.choices[0].message.content}
    except Exception as e:
        return {"error": str(e)}

def calculate_seo_score(content, keyword):
    if not content: return 0
    score = 0
    word_count = len(content.split())
    if word_count >= 300: score += 30
    elif word_count >= 150: score += 15
    if keyword and keyword.lower() in content.lower(): score += 30
    if word_count >= 500: score += 20
    return min(score, 100)

def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def landing():
    # NEW LANDING PAGE LOGIC
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # ORIGINAL HOME LOGIC MOVED HERE
    current_user.reset_monthly_limits()
    total_content = Content.query.filter_by(user_id=current_user.id).count()
    total_words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    avg_score = db.session.query(db.func.avg(Content.seo_score)).filter_by(user_id=current_user.id).scalar() or 0
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
    return render_template('index.html', total_content=total_content, 
                         total_words=total_words, avg_score=round(avg_score, 1), 
                         recent_content=recent, limits=current_user.get_limits())

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            username = data.get('username', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            if User.query.filter_by(email=email).first():
                return jsonify({'error': 'Email taken'}), 400
            user = User(username=username, email=email)
            user.set_password(password)
            if User.query.count() == 0: user.is_admin = True
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email', '').lower()).first()
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

# --- TOOLS ---
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
# Add the rest of your template routes here (schema, meta-tags, etc) using the same pattern

# --- API ---
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
        c = Content(user_id=current_user.id, title=data.get('title'), 
                   content=data.get('content'), keyword=data.get('keyword'))
        db.session.add(c)
        current_user.content_count += 1
        db.session.commit()
        return jsonify({'success': True, 'id': c.id})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@api_login_required
def api_generate_content():
    if not current_user.can_use_ai(): return jsonify({'error': 'Limit reached'}), 403
    data = request.get_json()
    res = call_openai(f"Write SEO article about {data.get('keyword')}", 2000)
    if 'error' in res: return jsonify(res), 500
    current_user.increment_ai_usage()
    return jsonify({'success': True, 'content': res['content'], 'html_content': markdown.markdown(res['content'])})

# --- DEPLOYMENT SETUP ---
@app.route('/health')
def health(): return jsonify({'status': 'healthy'})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
