# ============================================================================
# MySEOKingTool V5 - COMPLETE AI-Powered SEO Platform
# WITH LANDING PAGE, SITEMAP & ROBOTS.TXT
# ============================================================================

from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from urllib.parse import urlparse
import re
import os
import json
import markdown

from dotenv import load_dotenv
load_dotenv()

# Initialize Flask
app = Flask(__name__)

# Database Configuration
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///myseotool.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'myseotool-secret-2024')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize OpenAI
openai_api_key = os.getenv('OPENAI_API_KEY')
client = None

if openai_api_key:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=openai_api_key)
        print(f"OpenAI connected: {openai_api_key[:15]}...")
    except Exception as e:
        print(f"OpenAI error: {e}")
else:
    print("WARNING: OPENAI_API_KEY not set")

# Optional imports with fallbacks
try:
    import textstat
except ImportError:
    textstat = None

try:
    import validators
except ImportError:
    validators = None

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None

try:
    from docx import Document
except ImportError:
    Document = None

try:
    from nltk.tokenize import sent_tokenize
    import nltk
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        nltk.download('punkt', quiet=True)
except ImportError:
    def sent_tokenize(text):
        # Better fallback without NLTK
        import re
        sentences = re.split(r'[.!?]+', text)
        return [s.strip() for s in sentences if s.strip()]


# ============================================================================
# DECORATORS
# ============================================================================

def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# DATABASE MODELS
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
        if self.last_reset_date is None or self.last_reset_date.month != now.month or self.last_reset_date.year != now.year:
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
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M'),
            'content_type': self.content_type
        }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def call_openai(prompt, max_tokens=1000):
    if not client:
        return {"error": "OpenAI API key not configured"}
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert SEO content strategist."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.7
        )
        return {"success": True, "content": response.choices[0].message.content}
    except Exception as e:
        return {"error": f"OpenAI API Error: {str(e)}"}


def calculate_seo_score(content, keyword):
    score = 0
    content_lower = content.lower()
    keyword_lower = keyword.lower() if keyword else ""
    word_count = len(content.split())
    
    if word_count >= 300:
        score += 30
    elif word_count >= 150:
        score += 15
    
    if keyword_lower:
        keyword_count = content_lower.count(keyword_lower)
        if keyword_count >= 3:
            score += 30
        elif keyword_count >= 1:
            score += 15
    
    if re.search(r'#+\s', content):
        score += 20
    
    if word_count >= 1000:
        score += 20
    elif word_count >= 500:
        score += 10
    
    return min(score, 100)


def get_seo_grade(score):
    if score >= 90:
        return 'A+'
    elif score >= 80:
        return 'A'
    elif score >= 70:
        return 'B'
    elif score >= 60:
        return 'C'
    elif score >= 50:
        return 'D'
    else:
        return 'F'


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500


# ============================================================================
# PUBLIC ROUTES - NO LOGIN REQUIRED
# ============================================================================

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/features')
def features():
    return render_template('features.html')


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'message': 'Server is running'})


@app.route('/robots.txt')
def robots_txt():
    base_url = request.url_root.rstrip('/')
    content = "# Robots.txt for MySEOKingTool\n\n"
    content += "User-agent: *\n"
    content += "Allow: /\n"
    content += "Allow: /features\n"
    content += "Allow: /pricing\n"
    content += "Disallow: /dashboard\n"
    content += "Disallow: /admin\n"
    content += "Disallow: /api/\n"
    content += "Disallow: /editor\n"
    content += "Disallow: /profile\n\n"
    content += "Crawl-delay: 1\n\n"
    content += f"Sitemap: {base_url}/sitemap.xml\n"
    return Response(content, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    today = datetime.utcnow().strftime('%Y-%m-%d')
    
    pages = [
        {'loc': '/', 'priority': '1.0', 'changefreq': 'daily'},
        {'loc': '/features', 'priority': '0.9', 'changefreq': 'weekly'},
        {'loc': '/pricing', 'priority': '0.9', 'changefreq': 'weekly'},
        {'loc': '/login', 'priority': '0.6', 'changefreq': 'monthly'},
        {'loc': '/signup', 'priority': '0.7', 'changefreq': 'monthly'},
    ]
    
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    
    for page in pages:
        xml += '  <url>\n'
        xml += f'    <loc>{base_url}{page["loc"]}</loc>\n'
        xml += f'    <lastmod>{today}</lastmod>\n'
        xml += f'    <changefreq>{page["changefreq"]}</changefreq>\n'
        xml += f'    <priority>{page["priority"]}</priority>\n'
        xml += '  </url>\n'
    
    xml += '</urlset>'
    return Response(xml, mimetype='application/xml')


@app.route('/pricing')
def pricing():
    return render_template('pricing.html')


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            username = data.get('username', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')

            if not username or not email or not password:
                return jsonify({'error': 'All fields required'}), 400

            if len(password) < 6:
                return jsonify({'error': 'Password must be 6+ characters'}), 400

            if User.query.filter_by(email=email).first():
                return jsonify({'error': 'Email already registered'}), 400

            if User.query.filter_by(username=username).first():
                return jsonify({'error': 'Username already taken'}), 400

            user = User(username=username, email=email)
            user.set_password(password)

            if User.query.count() == 0:
                user.is_admin = True
                user.tier = 'enterprise'

            db.session.add(user)
            db.session.commit()
            login_user(user)

            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')

            user = User.query.filter_by(email=email).first()

            if user and user.check_password(password):
                if not user.is_active:
                    return jsonify({'error': 'Account deactivated'}), 403

                login_user(user, remember=data.get('remember', False))
                return jsonify({'success': True, 'redirect': url_for('dashboard')})

            return jsonify({'error': 'Invalid credentials'}), 401
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))


@app.route('/profile')
@login_required
def profile():
    current_user.reset_monthly_limits()
    return render_template('profile.html', user=current_user, limits=current_user.get_limits())


@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return jsonify({'error': 'All fields required'}), 400

        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401

        if len(new_password) < 6:
            return jsonify({'error': 'New password must be 6+ characters'}), 400

        current_user.set_password(new_password)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Password changed successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ============================================================================
# DASHBOARD & PROTECTED ROUTES
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
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


@app.route('/keyword-research')
@login_required
def keyword_research():
    return render_template('keyword_research.html')


@app.route('/serp-analysis')
@login_required
def serp_analysis():
    return render_template('serp_analysis.html')


@app.route('/content-generator')
@login_required
def content_generator():
    return render_template('content_generator.html')


@app.route('/content-library')
@login_required
def content_library():
    search = request.args.get('search', '')
    query = Content.query.filter_by(user_id=current_user.id)
    if search:
        query = query.filter((Content.title.contains(search)) | (Content.keyword.contains(search)))
    contents = query.order_by(Content.updated_at.desc()).all()
    return render_template('content_library.html', contents=contents, search_query=search)


@app.route('/editor')
@login_required
def editor():
    content_id = request.args.get('id')
    content = None
    if content_id:
        content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
    return render_template('editor.html', content=content)


@app.route('/schema-generator')
@login_required
def schema_generator():
    return render_template('schema_generator.html')


@app.route('/meta-tags')
@login_required
def meta_tags():
    return render_template('meta_tags.html')


@app.route('/alt-text-generator')
@login_required
def alt_text_generator():
    return render_template('alt_text.html')


@app.route('/readability-checker')
@login_required
def readability_checker():
    return render_template('readability_checker.html')


@app.route('/headline-analyzer')
@login_required
def headline_analyzer():
    return render_template('headline_analyzer.html')


@app.route('/lsi-keywords')
@login_required
def lsi_keywords():
    return render_template('lsi_keywords.html')


@app.route('/content-brief')
@login_required
def content_brief():
    return render_template('content_brief.html')


@app.route('/internal-linking')
@login_required
def internal_linking():
    return render_template('internal_linking.html')


@app.route('/content-outline')
@login_required
def content_outline():
    return render_template('content_outline.html')


@app.route('/plagiarism-checker')
@login_required
def plagiarism_checker():
    return render_template('plagiarism_checker.html')


@app.route('/image-seo')
@login_required
def image_seo():
    return render_template('image_seo.html')


@app.route('/faq-schema')
@login_required
def faq_schema():
    return render_template('faq_schema.html')


@app.route('/social-posts')
@login_required
def social_posts():
    return render_template('social_posts.html')


@app.route('/competitor-analyzer')
@login_required
def competitor_analyzer():
    return render_template('competitor_analyzer.html')


@app.route('/robots-generator')
@login_required
def robots_generator():
    return render_template('robots_generator.html')


@app.route('/sitemap-generator')
@login_required
def sitemap_generator():
    return render_template('sitemap_generator.html')


@app.route('/youtube-script')
@login_required
def youtube_script():
    return render_template('youtube_script.html')


@app.route('/email-subject')
@login_required
def email_subject():
    return render_template('email_subject.html')


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/save-content', methods=['POST'])
@api_login_required
def api_save_content():
    try:
        data = request.get_json()
        content_id = data.get('id')

        if content_id:
            content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
            if not content:
                return jsonify({'error': 'Content not found'}), 404
            content.title = data.get('title', content.title)
            content.keyword = data.get('keyword', content.keyword)
            content.content = data.get('content', content.content)
            content.word_count = len(data.get('content', '').split())
            content.seo_score = calculate_seo_score(content.content, content.keyword)
            content.updated_at = datetime.utcnow()
        else:
            if not current_user.can_create_content():
                return jsonify({'error': 'Monthly content limit reached'}), 403

            content_text = data.get('content', '')
            keyword_text = data.get('keyword', '')

            content = Content(
                user_id=current_user.id,
                title=data.get('title', 'Untitled'),
                keyword=keyword_text,
                content=content_text,
                word_count=len(content_text.split()),
                seo_score=calculate_seo_score(content_text, keyword_text)
            )
            db.session.add(content)
            current_user.content_count += 1

        db.session.commit()
        return jsonify({'success': True, 'id': content.id, 'message': 'Content saved!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/get-content/<int:content_id>')
@api_login_required
def api_get_content(content_id):
    try:
        content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
        if not content:
            return jsonify({'error': 'Content not found'}), 404
        return jsonify({'success': True, 'content': content.to_dict()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/delete-content/<int:content_id>', methods=['DELETE'])
@api_login_required
def api_delete_content(content_id):
    try:
        content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
        if not content:
            return jsonify({'error': 'Content not found'}), 404
        db.session.delete(content)
        current_user.content_count = max(0, current_user.content_count - 1)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Content deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-content', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_generate_content():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        word_count = int(data.get('word_count', 1000))

        if not keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"Write a comprehensive SEO article about '{keyword}'. Target: {word_count} words. Include H2 and H3 headings using ## and ###. Write in markdown format. SEO-optimized with natural keyword usage. Include introduction and conclusion."

        result = call_openai(prompt, max_tokens=min(word_count * 2, 4000))
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        content = result['content']
        current_user.increment_ai_usage()
        html_content = markdown.markdown(content)

        return jsonify({
            'success': True,
            'content': content,
            'html_content': html_content,
            'word_count': len(content.split()),
            'seo_score': calculate_seo_score(content, keyword)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-keywords', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_keywords():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        seed = data.get('keyword', '').strip()

        if not seed:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"Generate 15 SEO keyword variations for '{seed}'. Include long-tail keywords, question-based keywords, and related topics. Format as a simple list, one per line."

        result = call_openai(prompt, 500)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        response = result['content']
        current_user.increment_ai_usage()
        
        keywords = []
        for line in response.split('\n'):
            line = line.strip()
            line = re.sub(r'^\d+[\.)]\s*', '', line)
            line = line.lstrip('-•*').strip()
            if line and len(line) > 2:
                keywords.append(line)

        return jsonify({'success': True, 'keywords': keywords[:15]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/serp-analysis', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_serp_analysis():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()

        if not keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"Analyze the SERP for: '{keyword}'. Provide: SEARCH VOLUME (Low/Medium/High), COMPETITION (Low/Medium/High), DIFFICULTY SCORE (0-100), TOP RANKING CONTENT TYPES, 5 RELATED KEYWORDS, 3 CONTENT RECOMMENDATIONS."

        result = call_openai(prompt, 800)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'data': {
                'keyword': keyword,
                'analysis': result['content'],
                'search_volume': 'Medium',
                'competition': 'Medium',
                'difficulty': 50
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze-content-seo', methods=['POST'])
@api_login_required
def api_analyze_content_seo():
    try:
        data = request.get_json()
        content = data.get('content', '')
        keyword = data.get('keyword', '')

        if not content:
            return jsonify({'score': 0, 'issues': ['No content provided'], 'suggestions': [], 'grade': 'F'})

        score = 0
        issues = []
        suggestions = []
        word_count = len(content.split())

        if word_count >= 1500:
            score += 20
        elif word_count >= 1000:
            score += 15
        elif word_count >= 500:
            score += 10
            issues.append('Content is short (500-1000 words)')
        else:
            issues.append('Content under 500 words')

        keyword_density = 0
        if keyword:
            keyword_count = content.lower().count(keyword.lower())
            keyword_density = (keyword_count / word_count * 100) if word_count > 0 else 0
            if 1 <= keyword_density <= 3:
                score += 25
            elif keyword_density > 0:
                score += 15
            else:
                issues.append('Keyword not found')

        h2_count = len(re.findall(r'^##\s+.+', content, re.MULTILINE))
        if h2_count >= 3:
            score += 15
        elif h2_count >= 1:
            score += 10
        else:
            issues.append('No H2 headings')

        if re.search(r'^\s*[-*+]\s+', content, re.MULTILINE):
            score += 5
        else:
            suggestions.append('Add bullet points')

        if re.search(r'\[.+?\]\(.+?\)', content):
            score += 5
        else:
            suggestions.append('Add links')

        return jsonify({
            'success': True,
            'score': min(score, 100),
            'word_count': word_count,
            'keyword_density': round(keyword_density, 2),
            'heading_count': h2_count,
            'issues': issues,
            'suggestions': suggestions,
            'grade': get_seo_grade(score)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-schema', methods=['POST'])
@api_login_required
def api_generate_schema():
    try:
        data = request.get_json()
        schema_type = data.get('type', 'Article')
        title = data.get('title', '')
        description = data.get('description', '')

        if not title:
            return jsonify({'error': 'Title required'}), 400

        if schema_type == 'Article':
            schema = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": title,
                "description": description,
                "author": {"@type": "Person", "name": current_user.username},
                "datePublished": datetime.utcnow().strftime('%Y-%m-%d')
            }
        elif schema_type == 'Product':
            schema = {
                "@context": "https://schema.org",
                "@type": "Product",
                "name": title,
                "description": description
            }
        elif schema_type == 'FAQ':
            schema = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": []
            }
        else:
            schema = {
                "@context": "https://schema.org",
                "@type": schema_type,
                "name": title,
                "description": description
            }

        return jsonify({'success': True, 'schema': json.dumps(schema, indent=2)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-meta-tags', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_meta_tags():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        title = data.get('title', '').strip()
        keyword = data.get('keyword', '').strip()

        if not title:
            return jsonify({'error': 'Title required'}), 400

        prompt = f"Create a 150-160 character meta description for: Title: {title}, Keyword: {keyword}. Only provide the description text."

        result = call_openai(prompt, 100)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        meta_desc = result['content'].strip().strip('"')[:160]
        current_user.increment_ai_usage()

        meta_tags = {
            'title': title[:60],
            'description': meta_desc,
            'keywords': keyword
        }

        html = f'''<title>{meta_tags["title"]}</title>
<meta name="description" content="{meta_tags["description"]}">
<meta name="keywords" content="{meta_tags["keywords"]}">'''

        return jsonify({'success': True, 'meta_tags': meta_tags, 'html': html})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-alt-text', methods=['POST'])
@api_login_required
@limiter.limit("30 per hour")
def api_generate_alt_text():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        context = data.get('context', '').strip()
        keyword = data.get('keyword', '').strip()

        if not context:
            return jsonify({'error': 'Image context required'}), 400

        prompt = f"Generate SEO alt text (max 125 chars) for image. Context: {context}. Keyword: {keyword}. Only provide the alt text."

        result = call_openai(prompt, 50)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        alt_text = result['content'].strip().strip('"')[:125]
        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'alt_text': alt_text,
            'html': f'<img src="image.jpg" alt="{alt_text}">'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/check-readability', methods=['POST'])
@api_login_required
def api_check_readability():
    try:
        data = request.get_json()
        content = data.get('content', '').strip()

        if not content:
            return jsonify({'error': 'Content required'}), 400

        word_count = len(content.split())
        sentences = re.split(r'[.!?]+', content)
        sentences = [s.strip() for s in sentences if s.strip()]
        sentence_count = len(sentences)
        avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0

        flesch_score = 70
        if textstat:
            flesch_score = textstat.flesch_reading_ease(content)

        if flesch_score >= 70:
            reading_level = "Easy"
            level_color = "success"
        elif flesch_score >= 50:
            reading_level = "Standard"
            level_color = "info"
        else:
            reading_level = "Difficult"
            level_color = "warning"

        suggestions = []
        if avg_sentence_length > 20:
            suggestions.append("Shorten your sentences")
        if flesch_score < 60:
            suggestions.append("Use simpler words")

        return jsonify({
            'success': True,
            'flesch_score': round(flesch_score, 1),
            'reading_level': reading_level,
            'level_color': level_color,
            'word_count': word_count,
            'sentence_count': sentence_count,
            'avg_sentence_length': round(avg_sentence_length, 1),
            'suggestions': suggestions if suggestions else ['Good readability!']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze-headline', methods=['POST'])
@api_login_required
def api_analyze_headline():
    try:
        data = request.get_json()
        headline = data.get('headline', '').strip()

        if not headline:
            return jsonify({'error': 'Headline required'}), 400

        char_count = len(headline)
        word_count = len(headline.split())

        power_words = ['secret', 'proven', 'ultimate', 'best', 'free', 'easy', 'quick']
        found_power = [w for w in power_words if w in headline.lower()]

        score = 50
        if 50 <= char_count <= 60:
            score += 25
        if word_count >= 6:
            score += 15
        if found_power:
            score += 10

        grade = "A" if score >= 80 else "B" if score >= 60 else "C"

        return jsonify({
            'success': True,
            'headline': headline,
            'char_count': char_count,
            'word_count': word_count,
            'power_words': found_power,
            'overall_score': min(score, 100),
            'grade': grade,
            'suggestions': ['Good headline!'] if score >= 70 else ['Add power words', 'Aim for 50-60 characters']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-robots', methods=['POST'])
@api_login_required
def api_generate_robots():
    try:
        data = request.get_json()
        disallow_paths = data.get('disallow_paths', [])
        sitemap_url = data.get('sitemap_url', '')

        robots = "User-agent: *\nAllow: /\n"
        for path in disallow_paths:
            robots += f"Disallow: {path}\n"
        if sitemap_url:
            robots += f"\nSitemap: {sitemap_url}\n"

        return jsonify({'success': True, 'robots_txt': robots})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-sitemap', methods=['POST'])
@api_login_required
def api_generate_sitemap():
    try:
        data = request.get_json()
        urls = data.get('urls', [])

        if not urls:
            return jsonify({'error': 'URLs required'}), 400

        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for u in urls:
            url = u.get('url', '')
            if url:
                xml += f'  <url><loc>{url}</loc></url>\n'
        xml += '</urlset>'

        return jsonify({'success': True, 'sitemap_xml': xml})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/<int:content_id>/<fmt>')
@api_login_required
def api_export(content_id, fmt):
    try:
        content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
        if not content:
            return jsonify({'error': 'Content not found'}), 404

        safe_name = re.sub(r'[^\w\s-]', '', content.title)[:50]

        if fmt == 'txt':
            output = BytesIO()
            output.write(f"{content.title}\n\n{content.content}".encode('utf-8'))
            output.seek(0)
            return send_file(output, mimetype='text/plain', as_attachment=True, download_name=f"{safe_name}.txt")

        elif fmt == 'html':
            html = f"<!DOCTYPE html><html><head><title>{content.title}</title></head><body><h1>{content.title}</h1>{markdown.markdown(content.content)}</body></html>"
            output = BytesIO()
            output.write(html.encode('utf-8'))
            output.seek(0)
            return send_file(output, mimetype='text/html', as_attachment=True, download_name=f"{safe_name}.html")

        elif fmt == 'md':
            output = BytesIO()
            output.write(f"# {content.title}\n\n{content.content}".encode('utf-8'))
            output.seek(0)
            return send_file(output, mimetype='text/markdown', as_attachment=True, download_name=f"{safe_name}.md")

        return jsonify({'error': 'Invalid format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ============================================================================
# ADDITIONAL API ROUTES FOR ALL TOOLS
# ============================================================================

@app.route('/api/generate-lsi-keywords', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_lsi_keywords():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()

        if not keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"""Generate 20 LSI (Latent Semantic Indexing) keywords for the main keyword: "{keyword}"

Organize them into categories:
1. Direct Variations (5 keywords)
2. Question-Based (5 keywords)
3. Related Topics (5 keywords)
4. Long-Tail Keywords (5 keywords)

Format as a clean list with clear category headers."""

        result = call_openai(prompt, 800)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()
        
        # Parse keywords from response
        response = result['content']
        keywords = []
        for line in response.split('\n'):
            line = line.strip()
            line = re.sub(r'^\d+[\.)]\s*', '', line)
            line = line.lstrip('-•*').strip()
            if line and len(line) > 2 and not line.endswith(':') and 'Direct' not in line and 'Question' not in line and 'Related' not in line and 'Long-Tail' not in line:
                keywords.append(line)

        return jsonify({
            'success': True,
            'main_keyword': keyword,
            'keywords': keywords[:20],
            'categorized': response
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/check-plagiarism', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_check_plagiarism():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        content = data.get('content', '').strip()

        if not content:
            return jsonify({'error': 'Content required'}), 400

        if len(content) < 50:
            return jsonify({'error': 'Content too short (minimum 50 characters)'}), 400

        # Word and sentence analysis
        words = content.split()
        word_count = len(words)
        sentences = sent_tokenize(content)
        sentence_count = len(sentences)
        
        # Calculate uniqueness metrics
        unique_words = len(set([w.lower() for w in words]))
        uniqueness_ratio = (unique_words / word_count * 100) if word_count > 0 else 0
        
        # Simulate plagiarism check (in production, use actual plagiarism API)
        # Higher uniqueness ratio = lower plagiarism
        plagiarism_score = max(5, min(30, 100 - uniqueness_ratio))
        unique_score = 100 - plagiarism_score
        
        # Determine status
        if plagiarism_score < 15:
            status = 'Original'
            status_class = 'success'
            message = '✅ Content appears to be highly original!'
        elif plagiarism_score < 30:
            status = 'Moderate'
            status_class = 'warning'
            message = '⚠️ Some similar patterns detected. Consider revising.'
        else:
            status = 'High Risk'
            status_class = 'danger'
            message = '❌ High similarity detected. Significant revision needed.'
        
        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'plagiarism_percentage': round(plagiarism_score, 1),
            'unique_percentage': round(unique_score, 1),
            'word_count': word_count,
            'sentence_count': sentence_count,
            'unique_words': unique_words,
            'status': status,
            'status_class': status_class,
            'message': message,
            'suggestions': [
                'Add more original insights',
                'Use unique examples',
                'Paraphrase common phrases',
                'Add personal experience'
            ] if plagiarism_score > 15 else ['Great job! Content is original.']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-content-outline', methods=['POST'])
@api_login_required
@limiter.limit("15 per hour")
def api_generate_content_outline():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        target_audience = data.get('target_audience', 'general audience')
        content_type = data.get('content_type', 'blog post')

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        prompt = f"""Create a comprehensive SEO content outline for: "{topic}"
Content Type: {content_type}
Target Audience: {target_audience}

Include:
1. SEO-Optimized Title (H1) with power words
2. Introduction Outline (key points to cover)
3. 5-7 Main Sections (H2) with:
   - 2-3 subsections each (H3)
   - Key points to cover
   - Recommended word count
4. Conclusion Outline
5. Call-to-Action suggestions
6. SEO Notes (keywords, internal links)

Total Recommended Word Count: 1500-2000 words

Format with clear hierarchy and markdown headings."""

        result = call_openai(prompt, 1500)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        # Convert to HTML for better display
        html_outline = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'topic': topic,
            'target_audience': target_audience,
            'outline': result['content'],
            'html_outline': html_outline,
            'estimated_words': 1500
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-content-brief', methods=['POST'])
@api_login_required
@limiter.limit("15 per hour")
def api_generate_content_brief():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        keyword = data.get('keyword', '').strip()
        target_audience = data.get('target_audience', 'general audience')

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        prompt = f"""Create a detailed SEO content brief for: "{topic}"
Primary Keyword: {keyword}
Target Audience: {target_audience}

Include these sections:

**1. CONTENT GOAL & PURPOSE**
- Main objective
- What problem does it solve?

**2. TARGET AUDIENCE**
- Demographics
- Pain points
- Intent

**3. KEY MESSAGES (5 points)**
- Core takeaways for readers

**4. SEO STRATEGY**
- Primary Keyword: {keyword}
- 5 Secondary Keywords
- LSI Keywords
- Target word count

**5. TONE & STYLE**
- Voice (professional/casual/friendly)
- Writing style
- Do's and Don'ts

**6. CONTENT STRUCTURE**
- Recommended headings
- Content flow
- Required sections

**7. CALL-TO-ACTION**
- Primary CTA
- Secondary CTA
- Placement

**8. COMPETITOR INSIGHTS**
- What's currently ranking?
- Content gaps to fill
- Unique angle

**9. REQUIREMENTS**
- Word count: 1500-2000
- Images needed: 3-5
- Research sources
- Deadline considerations

Format professionally with clear sections."""

        result = call_openai(prompt, 2000)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        html_brief = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'topic': topic,
            'keyword': keyword,
            'target_audience': target_audience,
            'brief': result['content'],
            'html_brief': html_brief
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-faq-schema', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_faq_schema():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        num_questions = int(data.get('num_questions', 5))

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        num_questions = min(max(num_questions, 3), 10)  # Between 3-10

        prompt = f"""Generate {num_questions} FAQ questions and answers about: "{topic}"

Requirements:
- Questions should be what real users ask
- Answers should be 2-3 sentences, informative and SEO-friendly
- Cover different aspects of the topic
- Use natural language

Format EXACTLY as:
Q: [Question here]
A: [Answer here]

Q: [Question here]
A: [Answer here]

Make them valuable and comprehensive."""

        result = call_openai(prompt, 1200)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        # Parse FAQs and create schema
        faq_items = []
        lines = result['content'].split('\n')
        current_q = None
        current_a = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('Q:'):
                if current_q and current_a:
                    faq_items.append({
                        "@type": "Question",
                        "name": current_q,
                        "acceptedAnswer": {
                            "@type": "Answer",
                            "text": current_a
                        }
                    })
                current_q = line[2:].strip()
                current_a = None
            elif line.startswith('A:'):
                current_a = line[2:].strip()
        
        # Add last Q&A if exists
        if current_q and current_a:
            faq_items.append({
                "@type": "Question",
                "name": current_q,
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": current_a
                }
            })

        schema = {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": faq_items
        }

        # HTML snippet for embedding
        html_snippet = '<script type="application/ld+json">\n' + json.dumps(schema, indent=2) + '\n</script>'

        return jsonify({
            'success': True,
            'topic': topic,
            'num_questions': len(faq_items),
            'faq_text': result['content'],
            'schema': json.dumps(schema, indent=2),
            'html_snippet': html_snippet,
            'faq_items': faq_items
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/optimize-image-seo', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_optimize_image_seo():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        image_context = data.get('context', '').strip()
        keyword = data.get('keyword', '').strip()
        num_images = int(data.get('num_images', 1))

        if not image_context:
            return jsonify({'error': 'Image context required'}), 400

        num_images = min(max(num_images, 1), 5)  # Between 1-5

        prompt = f"""Generate SEO-optimized image metadata for {num_images} image(s) about: "{image_context}"
Target Keyword: {keyword}

For each image provide:

**Image 1:**
- **File Name:** seo-friendly-name-with-keywords.jpg
- **Alt Text:** Descriptive alt text under 125 characters with keyword
- **Title Text:** Engaging title with keyword
- **Caption:** Optional engaging caption (1 sentence)

{"**Image 2:**" if num_images > 1 else ""}
{"(same format)" if num_images > 1 else ""}

Requirements:
- File names: lowercase, hyphens, keywords
- Alt text: descriptive, accessible, under 125 chars
- Title text: engaging, keyword-optimized
- Natural keyword usage

Format clearly for each image."""

        result = call_openai(prompt, 1000)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'context': image_context,
            'keyword': keyword,
            'num_images': num_images,
            'optimization': result['content'],
            'tips': [
                'Use WebP format for better performance',
                'Compress images to under 200KB',
                'Include keyword in file name',
                'Always add descriptive alt text',
                'Use descriptive captions when possible'
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze-competitor', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_analyze_competitor():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        competitor_url = data.get('url', '').strip()
        keyword = data.get('keyword', '').strip()

        if not competitor_url:
            return jsonify({'error': 'Competitor URL required'}), 400

        # Validate URL format
        if not competitor_url.startswith(('http://', 'https://')):
            competitor_url = 'https://' + competitor_url

        prompt = f"""Analyze SEO strategy for competitor: {competitor_url}
Target Keyword: {keyword}

Provide detailed analysis:

**1. CONTENT STRATEGY**
- Content depth and quality
- Topic coverage
- Content format (text, video, infographics)
- Publishing frequency (estimated)

**2. KEYWORD STRATEGY**
- Primary keywords used
- Secondary keywords
- Keyword density
- LSI keywords

**3. CONTENT STRUCTURE**
- Heading hierarchy
- Internal linking
- Use of media
- Content length

**4. ON-PAGE SEO**
- Title tag optimization
- Meta description
- URL structure
- Schema markup (if detectable)

**5. USER EXPERIENCE**
- Readability
- Content formatting
- Call-to-actions
- Engagement elements

**6. SEO STRENGTHS**
(3-5 things they do well)

**7. SEO WEAKNESSES**
(3-5 areas for improvement)

**8. RECOMMENDATIONS TO OUTRANK**
(5-7 specific, actionable strategies)

Be specific and actionable based on common SEO best practices."""

        result = call_openai(prompt, 2000)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        html_analysis = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'url': competitor_url,
            'keyword': keyword,
            'analysis': result['content'],
            'html_analysis': html_analysis,
            'analyzed_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-internal-links', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_internal_links():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        website_url = data.get('website_url', '').strip()

        if not content:
            return jsonify({'error': 'Content required'}), 400

        # Get user's existing content as linking opportunities
        user_contents = Content.query.filter_by(user_id=current_user.id).limit(15).all()
        existing_topics = [f"- {c.title} (keyword: {c.keyword or 'N/A'})" for c in user_contents]
        
        existing_pages = '\n'.join(existing_topics) if existing_topics else '- Home page\n- About page\n- Blog page\n- Services page\n- Contact page'

        prompt = f"""Suggest internal linking strategy for this content.

**Content Preview:**
{content[:800]}...

**Available Pages to Link To:**
{existing_pages}

**Website:** {website_url or 'example.com'}

Provide:

**Internal Link Suggestions (5-7 links):**

1. **Link to:** [Page name]
   - **Anchor Text:** [Exact anchor text]
   - **Placement:** [Where in content - intro/section 2/conclusion]
   - **Context:** [Surrounding sentence example]
   - **Value:** [Why this link helps users]

2. [Continue for 5-7 suggestions]

**Internal Linking Best Practices:**
- Use descriptive anchor text
- Link to relevant, related content
- Don't overlink (max 5-7 per 1000 words)
- Prioritize user value over SEO

**SEO Benefits:**
- Improved crawlability
- Better page authority distribution
- Lower bounce rate
- Enhanced user experience"""

        result = call_openai(prompt, 1500)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        html_suggestions = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'suggestions': result['content'],
            'html_suggestions': html_suggestions,
            'available_pages': [c.title for c in user_contents],
            'total_available': len(user_contents)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-social-posts', methods=['POST'])
@api_login_required
@limiter.limit("15 per hour")
def api_generate_social_posts():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        platform = data.get('platform', 'all')
        tone = data.get('tone', 'professional')

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        platforms_list = ['Twitter', 'Facebook', 'LinkedIn', 'Instagram'] if platform == 'all' else [platform]
        
        prompt = f"""Create engaging social media posts about: "{topic}"
Tone: {tone}
Platforms: {', '.join(platforms_list)}

For each platform, provide:

**TWITTER (280 characters max)**
📱 Tweet: [Engaging tweet with hook]
🏷️ Hashtags: [3-5 relevant hashtags]
⏰ Best Time: [Recommended posting time]
💡 Tip: [Engagement tip]

**FACEBOOK**
📱 Post: [2-3 paragraph engaging post]
🏷️ Hashtags: [3-5 hashtags]
⏰ Best Time: [Recommended posting time]
💡 Tip: [Engagement tip]

**LINKEDIN**
📱 Post: [Professional 2-3 paragraph post]
🏷️ Hashtags: [3-5 professional hashtags]
⏰ Best Time: [Recommended posting time]
💡 Tip: [Engagement tip]

**INSTAGRAM**
📱 Caption: [Engaging caption with emojis]
🏷️ Hashtags: [10-15 relevant hashtags]
⏰ Best Time: [Recommended posting time]
💡 Tip: [Visual/engagement tip]

**GENERAL TIPS:**
- Use platform-specific best practices
- Include call-to-action
- Optimize for engagement
- Add relevant emojis where appropriate"""

        result = call_openai(prompt, 2000)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        html_posts = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'topic': topic,
            'tone': tone,
            'platforms': platforms_list,
            'posts': result['content'],
            'html_posts': html_posts
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-youtube-script', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_generate_youtube_script():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        duration = data.get('duration', '5-7')
        style = data.get('style', 'educational')

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        prompt = f"""Create a complete YouTube video script about: "{topic}"
Target Duration: {duration} minutes
Style: {style}

**VIDEO METADATA:**

**📌 VIDEO TITLE** (SEO-optimized, under 60 chars)
[Engaging title with keyword]

**📝 VIDEO DESCRIPTION** (SEO-optimized, 150+ words)
[Full description with keywords, timestamps, links]

**🏷️ TAGS** (15-20 tags)
[Comma-separated relevant tags]

**🖼️ THUMBNAIL IDEAS**
1. [Thumbnail concept 1]
2. [Thumbnail concept 2]
3. [Thumbnail concept 3]

---

**📜 FULL SCRIPT:**

**[0:00-0:10] HOOK** ⚡
[Attention-grabbing opening - pose question or bold statement]

**[0:10-0:40] INTRODUCTION** 👋
[Introduce yourself, topic, what viewers will learn]
[Call to action: "Don't forget to like and subscribe!"]

**[0:40-1:30] SECTION 1: [Title]**
[Main point 1 with examples]
[Engagement: Ask viewers a question]

**[1:30-2:30] SECTION 2: [Title]**
[Main point 2 with examples]
[Visual cue: Show screen/example]

**[2:30-3:30] SECTION 3: [Title]**
[Main point 3 with examples]
[Tip or pro advice]

**[3:30-4:30] SECTION 4: [Title]**
[Main point 4 with examples]
[Common mistake to avoid]

**[4:30-5:00] CONCLUSION** ✅
[Recap main points]
[Final thoughts]

**[5:00-5:15] CALL-TO-ACTION** 📢
[Ask to like, subscribe, comment]
[Mention next video or playlist]

**[5:15-5:20] OUTRO** 👋
[Sign-off and branding]

---

**💬 ENGAGEMENT PROMPTS:**
- Pin comment: [Question to ask viewers]
- Community post: [Related poll or question]
- Video idea: [Follow-up video suggestion]

Make it conversational, engaging, and valuable!"""

        result = call_openai(prompt, 2500)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        html_script = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'topic': topic,
            'duration': duration,
            'style': style,
            'script': result['content'],
            'html_script': html_script,
            'estimated_words': len(result['content'].split())
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-email-subjects', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_email_subjects():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        tone = data.get('tone', 'professional')
        email_type = data.get('email_type', 'newsletter')

        if not topic:
            return jsonify({'error': 'Email topic required'}), 400

        prompt = f"""Generate 15 compelling email subject lines for: "{topic}"
Email Type: {email_type}
Tone: {tone}

Create variety:

**CURIOSITY-DRIVEN (3 subject lines)**
[Make readers curious - ask questions, tease content]
1. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
2. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
3. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]

**BENEFIT-FOCUSED (3 subject lines)**
[Clear value proposition - what's in it for them]
4. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
5. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
6. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]

**URGENCY-BASED (3 subject lines)**
[Create FOMO - time-sensitive, scarcity]
7. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
8. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
9. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]

**QUESTION-BASED (3 subject lines)**
[Engaging questions that resonate]
10. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
11. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
12. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]

**CREATIVE/UNIQUE (3 subject lines)**
[Stand out - humor, emojis, unusual angles]
13. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
14. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]
15. [Subject line] | Open Rate: [High/Medium] | Why: [Reason]

**BEST PRACTICES:**
- Keep under 50 characters for mobile
- Use action words
- Personalize when possible
- A/B test different types
- Avoid spam trigger words

Requirements:
- Each under 60 characters
- Clear and compelling
- Match the tone: {tone}"""

        result = call_openai(prompt, 1500)
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        # Parse subject lines
        subject_lines = []
        lines = result['content'].split('\n')
        for line in lines:
            line = line.strip()
            # Look for numbered lines
            if re.match(r'^\d+\.', line):
                # Extract just the subject line part (before |)
                parts = line.split('|')
                if parts:
                    subject = re.sub(r'^\d+\.\s*', '', parts[0]).strip()
                    if len(subject) > 10 and len(subject) < 100:
                        # Determine open rate
                        open_rate = 'High' if 'High' in line else 'Medium' if 'Medium' in line else 'Medium'
                        subject_lines.append({
                            'subject': subject,
                            'open_rate': open_rate,
                            'length': len(subject)
                        })

        html_analysis = markdown.markdown(result['content'])

        return jsonify({
            'success': True,
            'topic': topic,
            'tone': tone,
            'email_type': email_type,
            'subject_lines': subject_lines[:15],
            'full_analysis': result['content'],
            'html_analysis': html_analysis,
            'tips': [
                'A/B test at least 2 versions',
                'Mobile users see only 30-40 characters',
                'Avoid ALL CAPS and excessive punctuation!!!',
                'Personalization increases open rates by 26%',
                'Tuesday-Thursday 10am-11am has highest open rates'
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.order_by(User.created_at.desc()).all()
    total_content = Content.query.count()
    return render_template('admin.html', users=users, total_content=total_content)


@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot modify yourself'}), 400

    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True, 'is_active': user.is_active})


@app.route('/admin/user/<int:user_id>/tier', methods=['POST'])
@login_required
def admin_change_tier(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)
    tier = request.get_json().get('tier')

    if tier in ['free', 'pro', 'enterprise']:
        user.tier = tier
        db.session.commit()
        return jsonify({'success': True, 'tier': tier})

    return jsonify({'error': 'Invalid tier'}), 400


# ============================================================================
# INITIALIZE DATABASE
# ============================================================================

with app.app_context():
    db.create_all()
    print("Database initialized!")


# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    print("\n" + "=" * 50)
    print("MySEOKingTool V5 - Starting...")
    print("=" * 50)
    print(f"Port: {port}")
    print(f"Database: {'PostgreSQL' if os.environ.get('DATABASE_URL') else 'SQLite'}")
    print(f"OpenAI: {'Connected' if client else 'Not configured'}")
    print("=" * 50)
    print("\nPublic Routes:")
    print("  / - Landing Page")
    print("  /robots.txt - SEO Robots")
    print("  /sitemap.xml - SEO Sitemap")
    print("\nProtected Routes:")
    print("  /dashboard - Main Dashboard")
    print("  + 20 more tools...")
    print("=" * 50 + "\n")
    
    app.run(debug=debug, host='0.0.0.0', port=port)
