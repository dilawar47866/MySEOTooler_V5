# Import statements - properly formatted
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import re
import os
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from docx import Document
from docx.shared import Pt, Inches
from io import BytesIO
import json
import textstat
import validators
from collections import Counter
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from functools import wraps

# Load environment
load_dotenv()

# Initialize Flask
app = Flask(__name__)

# Database Configuration - Railway Compatible
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///myseotoolver5.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'myseotoolver5-secret-2024')
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

# Initialize OpenAI - WITH PROPER ERROR CHECKING
openai_api_key = os.getenv('OPENAI_API_KEY')

if openai_api_key:
    print(f"🔑 API Key Found: {openai_api_key[:15]}...")
    client = OpenAI(api_key=openai_api_key)
else:
    print("⚠️  WARNING: OPENAI_API_KEY not set in environment variables!")
    client = None

# ============================================================================
# CUSTOM DECORATOR FOR API ROUTES (Returns JSON instead of redirect)
# ============================================================================

def api_login_required(f):
    """Custom login_required that returns JSON for API routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required. Please log in.'}), 401
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
        if self.last_reset_date.month != now.month or self.last_reset_date.year != now.year:
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
# HELPER FUNCTIONS - FIXED TO RETURN JSON-SAFE ERRORS
# ============================================================================

def call_openai(prompt, max_tokens=1000):
    """Call OpenAI API with error handling - RETURNS DICT FOR JSON SAFETY"""
    if not client:
        return {"error": "OpenAI API key not configured. Please set OPENAI_API_KEY in Railway environment variables."}
    
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
    """Calculate basic SEO score"""
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
    """Convert score to letter grade"""
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
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

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

            return jsonify({'success': True, 'redirect': url_for('index')})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

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
                return jsonify({'success': True, 'redirect': url_for('index')})

            return jsonify({'error': 'Invalid credentials'}), 401
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route('/')
@login_required
def index():
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
# API ROUTES - ALL FIXED TO RETURN JSON
# ============================================================================

@app.route('/api/check-readability', methods=['POST'])
@api_login_required
def api_check_readability():
    """Analyze content readability"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()

        if not content:
            return jsonify({'error': 'Content required'}), 400

        flesch_score = textstat.flesch_reading_ease(content)
        flesch_grade = textstat.flesch_kincaid_grade(content)

        word_count = len(content.split())
        sentences = re.split(r'[.!?]+', content)
        sentences = [s.strip() for s in sentences if s.strip()]
        sentence_count = len(sentences)
        avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0

        syllable_count = textstat.syllable_count(content)

        words = content.split()
        complex_words = sum(1 for word in words if textstat.syllable_count(word) >= 3)
        complex_word_percentage = (complex_words / word_count * 100) if word_count > 0 else 0

        passive_indicators = ['was', 'were', 'been', 'being', 'is', 'are', 'am']
        passive_count = sum(content.lower().count(f' {word} ') for word in passive_indicators)

        transition_words = ['however', 'therefore', 'furthermore', 'moreover', 'additionally',
                          'consequently', 'meanwhile', 'nevertheless', 'thus', 'hence']
        transition_count = sum(content.lower().count(word) for word in transition_words)

        if flesch_score >= 90:
            reading_level = "Very Easy (5th grade)"
            level_color = "success"
        elif flesch_score >= 80:
            reading_level = "Easy (6th grade)"
            level_color = "success"
        elif flesch_score >= 70:
            reading_level = "Fairly Easy (7th grade)"
            level_color = "info"
        elif flesch_score >= 60:
            reading_level = "Standard (8th-9th grade)"
            level_color = "info"
        elif flesch_score >= 50:
            reading_level = "Fairly Difficult (10th-12th grade)"
            level_color = "warning"
        elif flesch_score >= 30:
            reading_level = "Difficult (College)"
            level_color = "warning"
        else:
            reading_level = "Very Difficult (College Graduate)"
            level_color = "danger"

        suggestions = []

        if flesch_score < 60:
            suggestions.append("Consider using shorter sentences and simpler words")

        if avg_sentence_length > 20:
            suggestions.append(f"Average sentence length is {avg_sentence_length:.1f} words. Aim for 15-20 words")

        if complex_word_percentage > 15:
            suggestions.append(f"{complex_word_percentage:.1f}% of words are complex. Try to simplify")

        if passive_count > word_count * 0.1:
            suggestions.append("Too much passive voice detected. Use active voice")

        if transition_count < sentence_count * 0.3:
            suggestions.append("Add more transition words to improve flow")

        if not suggestions:
            suggestions.append("Great job! Your content is well-optimized for readability")

        return jsonify({
            'success': True,
            'flesch_score': round(flesch_score, 1),
            'grade_level': round(flesch_grade, 1),
            'reading_level': reading_level,
            'level_color': level_color,
            'word_count': word_count,
            'sentence_count': sentence_count,
            'avg_sentence_length': round(avg_sentence_length, 1),
            'complex_words': complex_words,
            'complex_word_percentage': round(complex_word_percentage, 1),
            'passive_voice_count': passive_count,
            'transition_words': transition_count,
            'suggestions': suggestions
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-headline', methods=['POST'])
@api_login_required
def api_analyze_headline():
    """Analyze headline effectiveness"""
    try:
        data = request.get_json()
        headline = data.get('headline', '').strip()

        if not headline:
            return jsonify({'error': 'Headline required'}), 400

        char_count = len(headline)
        word_count = len(headline.split())

        power_words = [
            'secret', 'proven', 'ultimate', 'essential', 'perfect', 'best', 'amazing',
            'incredible', 'exclusive', 'limited', 'bonus', 'free', 'guarantee', 'easy',
            'simple', 'quick', 'fast', 'instant', 'shocking', 'surprising', 'mind-blowing',
            'revolutionary', 'breakthrough', 'powerful', 'effective', 'complete', 'definitive'
        ]

        headline_lower = headline.lower()
        found_power_words = [word for word in power_words if word in headline_lower]
        power_word_count = len(found_power_words)

        emotional_words = [
            'love', 'hate', 'fear', 'angry', 'happy', 'sad', 'excited', 'thrilled',
            'worried', 'anxious', 'confident', 'proud', 'ashamed', 'guilty', 'jealous',
            'grateful', 'hopeful', 'disappointed', 'frustrated', 'overwhelmed'
        ]

        found_emotional_words = [word for word in emotional_words if word in headline_lower]
        emotional_count = len(found_emotional_words)

        common_words = ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']
        common_count = sum(1 for word in headline.lower().split() if word in common_words)

        all_words = set(headline.lower().split())
        uncommon_count = len(all_words) - common_count - power_word_count - emotional_count

        headline_type = "Generic"
        if headline.lower().startswith(('how to', 'how do', 'how can')):
            headline_type = "How-To"
        elif headline[0].isdigit() or any(word in headline_lower for word in ['ways', 'tips', 'reasons', 'steps']):
            headline_type = "List"
        elif headline.strip().endswith('?'):
            headline_type = "Question"
        elif any(word in headline_lower for word in ['guide', 'tutorial', 'introduction']):
            headline_type = "Guide"
        elif any(word in headline_lower for word in ['vs', 'versus', 'compared']):
            headline_type = "Comparison"

        if 50 <= char_count <= 60:
            seo_score = 100
            seo_feedback = "Perfect length for SEO"
        elif 40 <= char_count < 50:
            seo_score = 80
            seo_feedback = "Good, but could be slightly longer"
        elif 60 < char_count <= 70:
            seo_score = 80
            seo_feedback = "Good, but slightly long"
        else:
            seo_score = 50
            seo_feedback = "Too short or too long for optimal SEO"

        click_score = 0
        click_score += min(power_word_count * 15, 30)
        click_score += min(emotional_count * 10, 20)

        if headline[0].isdigit():
            click_score += 15

        if '?' in headline:
            click_score += 10

        if 6 <= word_count <= 10:
            click_score += 15
        elif word_count < 6:
            click_score += 5

        if 50 <= char_count <= 70:
            click_score += 10

        click_score = min(click_score, 100)
        overall_score = (seo_score + click_score) / 2

        if overall_score >= 80:
            grade = "A"
            grade_color = "success"
        elif overall_score >= 70:
            grade = "B"
            grade_color = "info"
        elif overall_score >= 60:
            grade = "C"
            grade_color = "warning"
        else:
            grade = "D"
            grade_color = "danger"

        suggestions = []

        if char_count < 40:
            suggestions.append("Headline is too short. Aim for 50-60 characters")
        elif char_count > 70:
            suggestions.append("Headline is too long. Keep it under 60 characters")

        if power_word_count == 0:
            suggestions.append("Add power words like 'ultimate', 'essential', 'proven' for impact")

        if word_count < 6:
            suggestions.append("Add more descriptive words. Aim for 6-10 words")

        if emotional_count == 0:
            suggestions.append("Include emotional triggers to increase engagement")

        if not headline[0].isdigit() and headline_type != "List":
            suggestions.append("Consider using numbers (e.g., '7 Ways to...')")

        if not suggestions:
            suggestions.append("Excellent headline! Well-optimized for SEO and clicks")

        total_words = word_count if word_count > 0 else 1
        word_balance = {
            'common': round((common_count / total_words) * 100),
            'uncommon': round((uncommon_count / total_words) * 100),
            'emotional': round((emotional_count / total_words) * 100),
            'power': round((power_word_count / total_words) * 100)
        }

        return jsonify({
            'success': True,
            'headline': headline,
            'char_count': char_count,
            'word_count': word_count,
            'headline_type': headline_type,
            'power_words': found_power_words,
            'power_word_count': power_word_count,
            'emotional_words': found_emotional_words,
            'emotional_count': emotional_count,
            'seo_score': round(seo_score),
            'seo_feedback': seo_feedback,
            'click_score': round(click_score),
            'overall_score': round(overall_score),
            'grade': grade,
            'grade_color': grade_color,
            'suggestions': suggestions,
            'word_balance': word_balance
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-lsi-keywords', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_lsi_keywords():
    """Generate LSI (semantically related) keywords using AI"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached for this month. Upgrade your plan!'}), 403

    try:
        data = request.get_json()
        main_keyword = data.get('keyword', '').strip()

        if not main_keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"""Generate 20 LSI (Latent Semantic Indexing) keywords for: "{main_keyword}"

LSI keywords are semantically related terms that help search engines understand context.

Provide:
1. Synonyms and variations
2. Related topics and concepts
3. Question-based keywords
4. Long-tail variations

Format as a simple numbered list, one keyword per line. Only provide the keywords, no explanations."""

        result = call_openai(prompt, 500)

        # Check if OpenAI returned an error
        if "error" in result:
            return jsonify({'error': result['error']}), 500

        response = result['content']
        current_user.increment_ai_usage()

        keywords = []
        for line in response.split('\n'):
            line = line.strip()
            line = re.sub(r'^\d+[\.)]\s*', '', line)
            line = line.lstrip('-•*').strip()

            if line and len(line) > 3:
                keywords.append(line)

        prompt2 = f"""Categorize these LSI keywords for "{main_keyword}" into groups:

Categories needed:
1. Synonyms & Variations
2. Related Concepts
3. Question Keywords
4. Long-tail Keywords

Provide 5 keywords for each category.
Format:
CATEGORY_NAME:
- keyword 1
- keyword 2
etc."""

        result2 = call_openai(prompt2, 600)
        
        if "error" not in result2:
            categorized_response = result2['content']
            current_user.increment_ai_usage()
        else:
            categorized_response = "Categorization unavailable"

        return jsonify({
            'success': True,
            'main_keyword': main_keyword,
            'keywords': keywords[:20],
            'categorized': categorized_response,
            'count': len(keywords[:20])
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content-brief', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_generate_content_brief():
    """Generate comprehensive content brief for a keyword"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached for this month'}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()

        if not keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"""Create a comprehensive SEO content brief for the keyword: "{keyword}"

Include:

1. TARGET AUDIENCE:
   - Who is this content for?
   - Pain points and needs

2. SEARCH INTENT:
   - Primary intent (informational/transactional/navigational)
   - User expectations

3. RECOMMENDED STRUCTURE:
   - Optimal word count
   - Suggested H2 headings (5-7)
   - Suggested H3 subheadings

4. KEY TOPICS TO COVER:
   - 10 main topics/sections

5. QUESTIONS TO ANSWER:
   - 8 common questions about this topic

6. LSI KEYWORDS TO INCLUDE:
   - 15 semantically related keywords

7. CONTENT ANGLE:
   - Unique angle/hook
   - Competitive advantage

8. CALL TO ACTION:
   - Recommended CTA

Format clearly with headers and bullet points."""

        result = call_openai(prompt, 1500)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'keyword': keyword,
            'brief': result['content']
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/suggest-internal-links', methods=['POST'])
@api_login_required
def api_suggest_internal_links():
    """Suggest internal links from content library"""
    try:
        data = request.get_json()
        current_content = data.get('content', '').strip()
        current_keyword = data.get('keyword', '').strip()

        if not current_content:
            return jsonify({'error': 'Content required'}), 400

        all_content = Content.query.filter_by(user_id=current_user.id).all()

        if len(all_content) < 2:
            return jsonify({
                'success': True,
                'suggestions': [],
                'message': 'Create more content to get internal linking suggestions'
            })

        current_words = set(re.findall(r'\b\w+\b', current_content.lower()))

        suggestions = []

        for content_item in all_content:
            if content_item.keyword == current_keyword and content_item.title in current_content:
                continue

            content_words = set(re.findall(r'\b\w+\b', content_item.content.lower()))
            common_words = current_words.intersection(content_words)

            stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}
            meaningful_words = common_words - stop_words

            if len(meaningful_words) >= 5:
                relevance = (len(meaningful_words) / len(current_words)) * 100

                anchor_text = content_item.keyword if content_item.keyword else content_item.title

                suggestions.append({
                    'id': content_item.id,
                    'title': content_item.title,
                    'keyword': content_item.keyword,
                    'anchor_text': anchor_text,
                    'relevance': round(relevance, 1),
                    'common_topics': list(meaningful_words)[:5]
                })

        suggestions.sort(key=lambda x: x['relevance'], reverse=True)

        return jsonify({
            'success': True,
            'suggestions': suggestions[:10],
            'total_content': len(all_content)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-outline', methods=['POST'])
@api_login_required
@limiter.limit("15 per hour")
def api_generate_outline():
    """Generate article outline with AI"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        outline_type = data.get('type', 'how-to')

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        type_instructions = {
            'how-to': 'Create a step-by-step how-to guide structure',
            'listicle': 'Create a numbered list article structure',
            'guide': 'Create a comprehensive guide structure',
            'comparison': 'Create a comparison article structure'
        }

        instruction = type_instructions.get(outline_type, 'Create an article structure')

        prompt = f"""{instruction} for the topic: "{topic}"

Provide a detailed outline with:

# Main Title
[Compelling title for the article]

## Introduction (150-200 words)
- Hook
- Problem statement
- What readers will learn

## Section Structure:
Provide 5-7 main sections (H2 headings) with:
- H2 heading
- 2-3 H3 subheadings under each H2
- Key points to cover in each section

## Conclusion (100-150 words)
- Summary
- Call to action

## Additional Elements:
- FAQ section (3-5 questions)
- Recommended word count for each section

Format with clear markdown headers."""

        result = call_openai(prompt, 1200)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'topic': topic,
            'outline': result['content']
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-plagiarism', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_check_plagiarism():
    """Simple plagiarism check against user's own content"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()

        if not content:
            return jsonify({'error': 'Content required'}), 400

        if len(content.split()) < 50:
            return jsonify({'error': 'Content must be at least 50 words'}), 400

        all_content = Content.query.filter_by(user_id=current_user.id).all()

        sentences = sent_tokenize(content)

        matches = []
        total_matched_sentences = 0

        for existing in all_content:
            existing_sentences = sent_tokenize(existing.content)

            for sent in sentences:
                sent_lower = sent.lower().strip()

                if len(sent_lower) < 30:
                    continue

                for ex_sent in existing_sentences:
                    ex_sent_lower = ex_sent.lower().strip()

                    words1 = set(sent_lower.split())
                    words2 = set(ex_sent_lower.split())

                    if len(words1) == 0:
                        continue

                    overlap = len(words1.intersection(words2))
                    similarity = (overlap / len(words1)) * 100

                    if similarity >= 70:
                        total_matched_sentences += 1
                        matches.append({
                            'original_sentence': sent,
                            'matched_sentence': ex_sent,
                            'similarity': round(similarity, 1),
                            'source_title': existing.title,
                            'source_id': existing.id
                        })
                        break

        total_sentences = len([s for s in sentences if len(s.split()) >= 5])
        similarity_percentage = (total_matched_sentences / total_sentences * 100) if total_sentences > 0 else 0

        if similarity_percentage < 10:
            verdict = "Original"
            verdict_color = "success"
        elif similarity_percentage < 30:
            verdict = "Mostly Original"
            verdict_color = "info"
        elif similarity_percentage < 50:
            verdict = "Some Matches"
            verdict_color = "warning"
        else:
            verdict = "High Similarity"
            verdict_color = "danger"

        return jsonify({
            'success': True,
            'similarity_percentage': round(similarity_percentage, 1),
            'verdict': verdict,
            'verdict_color': verdict_color,
            'total_sentences': total_sentences,
            'matched_sentences': total_matched_sentences,
            'matches': matches[:10],
            'total_matches': len(matches)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/optimize-image-seo', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_optimize_image_seo():
    """Generate SEO-optimized image attributes"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        images = data.get('images', [])
        keyword = data.get('keyword', '').strip()

        if not images:
            return jsonify({'error': 'At least one image description required'}), 400

        results = []

        for idx, image_desc in enumerate(images):
            prompt = f"""Generate SEO-optimized attributes for an image.

Image Description: {image_desc}
Target Keyword: {keyword}
Image Number: {idx + 1}

Provide:
1. ALT TEXT (125 chars max, descriptive, includes keyword if relevant)
2. FILE NAME (SEO-friendly, lowercase, hyphens)
3. TITLE TEXT (hover text, 60 chars)
4. CAPTION (engaging, 150 chars)

Format:
ALT: [text]
FILE: [filename.jpg]
TITLE: [text]
CAPTION: [text]"""

            result = call_openai(prompt, 200)

            if "error" not in result:
                response = result['content']
                
                alt_match = re.search(r'ALT:\s*(.+)', response)
                file_match = re.search(r'FILE:\s*(.+)', response)
                title_match = re.search(r'TITLE:\s*(.+)', response)
                caption_match = re.search(r'CAPTION:\s*(.+)', response)

                results.append({
                    'description': image_desc,
                    'alt_text': alt_match.group(1).strip() if alt_match else '',
                    'file_name': file_match.group(1).strip() if file_match else '',
                    'title_text': title_match.group(1).strip() if title_match else '',
                    'caption': caption_match.group(1).strip() if caption_match else '',
                    'html': f'<img src="{file_match.group(1).strip() if file_match else "image.jpg"}" alt="{alt_match.group(1).strip() if alt_match else ""}" title="{title_match.group(1).strip() if title_match else ""}">'
                })

                current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-faq-schema', methods=['POST'])
@api_login_required
@limiter.limit("15 per hour")
def api_generate_faq_schema():
    """Generate FAQ schema from content or topic"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        content = data.get('content', '').strip()

        if not topic and not content:
            return jsonify({'error': 'Topic or content required'}), 400

        if content:
            prompt = f"""Extract or generate 5-8 frequently asked questions from this content:

{content[:1000]}

For each question, provide a clear, concise answer (2-3 sentences).

Format:
Q: [question]
A: [answer]

(Repeat for each Q&A pair)"""
        else:
            prompt = f"""Generate 8 frequently asked questions and answers about: "{topic}"

Provide questions that users commonly search for. Each answer should be 2-3 sentences, clear and informative.

Format:
Q: [question]
A: [answer]

(Repeat for each Q&A pair)"""

        result = call_openai(prompt, 1000)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        response = result['content']
        current_user.increment_ai_usage()

        qa_pairs = []
        lines = response.split('\n')
        current_q = None
        current_a = None

        for line in lines:
            line = line.strip()
            if line.startswith('Q:'):
                if current_q and current_a:
                    qa_pairs.append({'question': current_q, 'answer': current_a})
                current_q = line[2:].strip()
                current_a = None
            elif line.startswith('A:'):
                current_a = line[2:].strip()

        if current_q and current_a:
            qa_pairs.append({'question': current_q, 'answer': current_a})

        schema = {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": []
        }

        for qa in qa_pairs:
            schema["mainEntity"].append({
                "@type": "Question",
                "name": qa['question'],
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": qa['answer']
                }
            })

        schema_json = json.dumps(schema, indent=2)

        return jsonify({
            'success': True,
            'qa_pairs': qa_pairs,
            'schema': schema_json,
            'count': len(qa_pairs)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-social-posts', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_social_posts():
    """Generate social media posts from content"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        platforms = data.get('platforms', ['twitter', 'linkedin', 'facebook'])

        if not content:
            return jsonify({'error': 'Content required'}), 400

        posts = {}

        if 'twitter' in platforms:
            prompt = f"""Create 3 engaging Twitter posts (280 chars max each) to promote this content:

{content[:500]}

Include:
- Hooks/questions
- Relevant hashtags (2-3)
- Emojis where appropriate

Provide 3 variations."""

            result = call_openai(prompt, 300)
            if "error" not in result:
                posts['twitter'] = result['content']
                current_user.increment_ai_usage()

        if 'linkedin' in platforms:
            prompt = f"""Create a professional LinkedIn post (1300 chars max) to promote this content:

{content[:500]}

Include:
- Professional hook
- Key insights
- Call to action
- 3-5 relevant hashtags

Tone: Professional but engaging."""

            result = call_openai(prompt, 400)
            if "error" not in result:
                posts['linkedin'] = result['content']
                current_user.increment_ai_usage()

        if 'facebook' in platforms:
            prompt = f"""Create an engaging Facebook post (500 chars) to promote this content:

{content[:500]}

Include:
- Conversational hook
- Value proposition
- Call to action
- 1-2 emojis

Tone: Friendly and engaging."""

            result = call_openai(prompt, 300)
            if "error" not in result:
                posts['facebook'] = result['content']
                current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'posts': posts
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-competitor', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_analyze_competitor():
    """Analyze competitor content structure"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL required'}), 400

        if not validators.url(url):
            return jsonify({'error': 'Invalid URL'}), 400

        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return jsonify({'error': f'Failed to fetch URL (Status: {response.status_code})'}), 400

        soup = BeautifulSoup(response.content, 'html.parser')

        title_tag = soup.find('title')
        title = title_tag.text if title_tag else 'No title found'

        meta_desc_tag = soup.find('meta', attrs={'name': 'description'})
        meta_desc = meta_desc_tag['content'] if meta_desc_tag and meta_desc_tag.get('content') else 'No meta description'

        h1_tags = [h.text.strip() for h in soup.find_all('h1')]
        h2_tags = [h.text.strip() for h in soup.find_all('h2')]
        h3_tags = [h.text.strip() for h in soup.find_all('h3')]

        paragraphs = soup.find_all('p')
        text_content = ' '.join([p.text for p in paragraphs])
        word_count = len(text_content.split())

        images = soup.find_all('img')
        image_count = len(images)
        images_with_alt = sum(1 for img in images if img.get('alt'))

        links = soup.find_all('a')
        internal_links = sum(1 for link in links if link.get('href', '').startswith('/') or urlparse(url).netloc in link.get('href', ''))
        external_links = len(links) - internal_links

        schema_tags = soup.find_all('script', attrs={'type': 'application/ld+json'})
        has_schema = len(schema_tags) > 0

        return jsonify({
            'success': True,
            'url': url,
            'analysis': {
                'title': title,
                'title_length': len(title),
                'meta_description': meta_desc,
                'meta_desc_length': len(meta_desc),
                'word_count': word_count,
                'h1_count': len(h1_tags),
                'h2_count': len(h2_tags),
                'h3_count': len(h3_tags),
                'h1_tags': h1_tags[:5],
                'h2_tags': h2_tags[:10],
                'image_count': image_count,
                'images_with_alt': images_with_alt,
                'alt_percentage': round((images_with_alt / image_count * 100) if image_count > 0 else 0, 1),
                'internal_links': internal_links,
                'external_links': external_links,
                'has_schema': has_schema,
                'schema_count': len(schema_tags)
            }
        })

    except requests.Timeout:
        return jsonify({'error': 'Request timeout. Try again.'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-robots', methods=['POST'])
@api_login_required
def api_generate_robots():
    """Generate robots.txt file"""
    try:
        data = request.get_json()

        allow_all = data.get('allow_all', True)
        disallow_paths = data.get('disallow_paths', [])
        sitemap_url = data.get('sitemap_url', '')
        crawl_delay = data.get('crawl_delay', 0)

        robots_txt = "# Robots.txt generated by MySEOKingTool\n\n"

        robots_txt += "User-agent: *\n"

        if allow_all and not disallow_paths:
            robots_txt += "Allow: /\n"
        else:
            if disallow_paths:
                for path in disallow_paths:
                    robots_txt += f"Disallow: {path}\n"
            else:
                robots_txt += "Disallow:\n"

        if crawl_delay > 0:
            robots_txt += f"Crawl-delay: {crawl_delay}\n"

        robots_txt += "\n"

        if sitemap_url:
            robots_txt += f"Sitemap: {sitemap_url}\n"

        robots_txt += "\n# Common best practices\n"
        robots_txt += "User-agent: Googlebot\n"
        robots_txt += "Allow: /\n"

        return jsonify({
            'success': True,
            'robots_txt': robots_txt
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-sitemap', methods=['POST'])
@api_login_required
def api_generate_sitemap():
    """Generate XML sitemap from URLs"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])

        if not urls:
            return jsonify({'error': 'At least one URL required'}), 400

        sitemap_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        sitemap_xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

        for url_data in urls:
            url = url_data.get('url', '').strip()
            priority = url_data.get('priority', '0.5')
            changefreq = url_data.get('changefreq', 'weekly')

            if not url:
                continue

            sitemap_xml += '  <url>\n'
            sitemap_xml += f'    <loc>{url}</loc>\n'
            sitemap_xml += f'    <lastmod>{datetime.utcnow().strftime("%Y-%m-%d")}</lastmod>\n'
            sitemap_xml += f'    <changefreq>{changefreq}</changefreq>\n'
            sitemap_xml += f'    <priority>{priority}</priority>\n'
            sitemap_xml += '  </url>\n'

        sitemap_xml += '</urlset>'

        return jsonify({
            'success': True,
            'sitemap_xml': sitemap_xml,
            'url_count': len(urls)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-youtube-script', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_generate_youtube_script():
    """Generate YouTube video script"""
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        duration = data.get('duration', '5-7')
        style = data.get('style', 'educational')

        if not topic:
            return jsonify({'error': 'Topic required'}), 400

        prompt = f"""Create a complete YouTube video script for a {duration} minute {style} video about: "{topic}"

Include:

1. HOOK (First 15 seconds)
   - Attention-grabbing opening
   - Why viewers should watch

2. INTRODUCTION (30 seconds)
   - Brief overview
   - What viewers will learn

3. MAIN CONTENT (Divide into 3-5 key sections)
   - Section headers
   - Talking points
   - Examples/tips

4. CONCLUSION (30 seconds)
   - Summary
   - Call to action (subscribe, like, comment)

5. VIDEO METADATA:
   - Optimized title (60 chars)
   - Description (150 words)
   - 10-15 relevant tags
   - 3 chapters with timestamps

Format clearly with timestamps."""

        result = call_openai(prompt, 1500)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'topic': topic,
            'script': result['content']
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-subject-line', methods=['POST'])
@api_login_required
def api_test_subject_line():
    """Analyze email subject line effectiveness"""
    try:
        data = request.get_json()
        subject = data.get('subject', '').strip()

        if not subject:
            return jsonify({'error': 'Subject line required'}), 400

        char_count = len(subject)
        word_count = len(subject.split())

        spam_words = ['free', 'buy now', 'click here', 'limited time', 'act now', '100%',
                     'guarantee', 'cash', 'winner', 'congratulations', '!!!', '$$$']
        found_spam = [word for word in spam_words if word.lower() in subject.lower()]
        spam_score = len(found_spam) * 20

        has_personalization = any(word in subject.lower() for word in ['you', 'your'])

        urgency_words = ['today', 'now', 'limited', 'urgent', 'ending', 'last chance']
        has_urgency = any(word in subject.lower() for word in urgency_words)

        has_numbers = bool(re.search(r'\d', subject))

        emoji_pattern = re.compile("["
                                  u"\U0001F600-\U0001F64F"
                                  u"\U0001F300-\U0001F5FF"
                                  "]+", flags=re.UNICODE)
        has_emoji = bool(emoji_pattern.search(subject))

        score = 50

        if 40 <= char_count <= 60:
            score += 20
        elif char_count > 60:
            score -= 10

        if has_personalization:
            score += 10

        if has_numbers:
            score += 10

        if has_urgency:
            score += 5

        if has_emoji:
            score += 5

        score -= spam_score
        score = max(0, min(100, score))

        if score >= 80:
            grade = "Excellent"
            grade_color = "success"
        elif score >= 60:
            grade = "Good"
            grade_color = "info"
        elif score >= 40:
            grade = "Fair"
            grade_color = "warning"
        else:
            grade = "Poor"
            grade_color = "danger"

        suggestions = []

        if char_count > 60:
            suggestions.append("Shorten subject line to 40-60 characters")
        elif char_count < 40:
            suggestions.append("Add more detail (aim for 40-60 characters)")

        if not has_personalization:
            suggestions.append("Add personalization ('you', 'your')")

        if not has_numbers:
            suggestions.append("Consider adding numbers for specificity")

        if found_spam:
            suggestions.append(f"Remove spam trigger words: {', '.join(found_spam)}")

        if not suggestions:
            suggestions.append("Great subject line!")

        predicted_open_rate = round(score * 0.35, 1)

        return jsonify({
            'success': True,
            'subject': subject,
            'score': round(score),
            'grade': grade,
            'grade_color': grade_color,
            'char_count': char_count,
            'word_count': word_count,
            'has_personalization': has_personalization,
            'has_urgency': has_urgency,
            'has_numbers': has_numbers,
            'has_emoji': has_emoji,
            'spam_words': found_spam,
            'predicted_open_rate': predicted_open_rate,
            'suggestions': suggestions
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# CORE API ROUTES - FIXED
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
                return jsonify({'error': 'Monthly content limit reached. Upgrade your plan!'}), 403

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
        return jsonify({'success': True, 'id': content.id, 'message': 'Content saved successfully!'})
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

        return jsonify({'success': True, 'message': 'Content deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def api_generate_content():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached for this month. Upgrade your plan!'}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        word_count = int(data.get('word_count', 1000))

        if not keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"""Write a comprehensive SEO article about "{keyword}".

Requirements:
- Target: {word_count} words
- Include H2 and H3 headings (use ## and ###)
- Write in markdown format
- SEO-optimized with natural keyword usage
- Include introduction and conclusion
- Use bullet points where appropriate"""

        result = call_openai(prompt, max_tokens=min(word_count * 2, 4000))

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        content = result['content']
        current_user.increment_ai_usage()

        html_content = markdown.markdown(content)
        actual_words = len(content.split())

        return jsonify({
            'success': True,
            'content': content,
            'html_content': html_content,
            'word_count': actual_words,
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

        prompt = f"""Generate 15 SEO keyword variations for "{seed}".

Include:
- Long-tail keywords
- Question-based keywords
- Related topics

Format as simple list, one per line."""

        result = call_openai(prompt, 500)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        response = result['content']
        current_user.increment_ai_usage()

        keywords = [line.strip().lstrip('-•*').strip() for line in response.split('\n')
                    if line.strip() and not line.strip().startswith('#')][:15]

        return jsonify({'success': True, 'keywords': keywords})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/serp-analysis', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_serp_analysis():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached. Upgrade your plan!'}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()

        if not keyword:
            return jsonify({'error': 'Keyword required'}), 400

        prompt = f"""Analyze the SERP (Search Engine Results Page) for: "{keyword}"

Provide detailed analysis in this exact format:

SEARCH VOLUME: [Low/Medium/High] (estimate)
COMPETITION: [Low/Medium/High]
DIFFICULTY SCORE: [0-100]

TOP RANKING CONTENT TYPES:
- [Type 1]
- [Type 2]
- [Type 3]

RELATED KEYWORDS:
1. [keyword variation 1]
2. [keyword variation 2]
3. [keyword variation 3]
4. [keyword variation 4]
5. [keyword variation 5]

CONTENT RECOMMENDATIONS:
- [Recommendation 1]
- [Recommendation 2]
- [Recommendation 3]

BEST PRACTICES:
- [Best practice 1]
- [Best practice 2]
- [Best practice 3]"""

        result = call_openai(prompt, 800)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        response = result['content']
        current_user.increment_ai_usage()

        lines = response.split('\n')
        parsed_data = {
            'keyword': keyword,
            'analysis': response,
            'search_volume': 'Medium',
            'competition': 'Medium',
            'difficulty': 50,
            'related_keywords': [],
            'recommendations': []
        }

        for line in lines:
            if 'SEARCH VOLUME:' in line:
                parsed_data['search_volume'] = line.split(':')[1].strip().split()[0]
            elif 'COMPETITION:' in line:
                parsed_data['competition'] = line.split(':')[1].strip().split()[0]
            elif 'DIFFICULTY SCORE:' in line:
                try:
                    parsed_data['difficulty'] = int(re.search(r'\d+', line).group())
                except:
                    pass
            elif line.strip().startswith(('1.', '2.', '3.', '4.', '5.')) and 'RELATED' in response[:response.index(line) if line in response else 0]:
                parsed_data['related_keywords'].append(line.split('.', 1)[1].strip())

        return jsonify({
            'success': True,
            'data': parsed_data
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
            suggestions.append('Add 500+ more words for better SEO')
        elif word_count >= 500:
            score += 10
            issues.append('Content is too short (500-1000 words)')
        else:
            issues.append('Critical: Content under 500 words')

        keyword_density = 0
        if keyword:
            content_lower = content.lower()
            keyword_lower = keyword.lower()
            keyword_count = content_lower.count(keyword_lower)
            keyword_density = (keyword_count / word_count * 100) if word_count > 0 else 0

            if 1 <= keyword_density <= 3:
                score += 25
            elif keyword_density > 0:
                score += 15
                if keyword_density > 3:
                    issues.append(f'Keyword density too high ({keyword_density:.1f}%)')
                else:
                    suggestions.append('Use keyword more naturally (aim for 1-3%)')
            else:
                issues.append('Keyword not found in content')

            first_100_words = ' '.join(content.split()[:100]).lower()
            if keyword_lower in first_100_words:
                score += 5
            else:
                suggestions.append('Include keyword in first paragraph')
        else:
            issues.append('No target keyword specified')

        h2_count = len(re.findall(r'^##\s+.+', content, re.MULTILINE))
        h3_count = len(re.findall(r'^###\s+.+', content, re.MULTILINE))

        if h2_count >= 3:
            score += 15
        elif h2_count >= 1:
            score += 10
            suggestions.append(f'Add more H2 headings (found {h2_count}, aim for 3+)')
        else:
            issues.append('No H2 headings found')

        if h3_count >= 2:
            score += 5
        elif h3_count == 0:
            suggestions.append('Add H3 subheadings for better structure')

        sentences = re.split(r'[.!?]+', content)
        sentences = [s for s in sentences if s.strip()]
        avg_sentence_length = sum(len(s.split()) for s in sentences) / len(sentences) if sentences else 0

        if 15 <= avg_sentence_length <= 20:
            score += 15
        elif 10 <= avg_sentence_length <= 25:
            score += 10
            suggestions.append('Optimize sentence length (15-20 words avg)')
        else:
            if avg_sentence_length > 25:
                issues.append('Sentences too long (reduce complexity)')
            else:
                suggestions.append('Vary sentence length for better flow')

        if re.search(r'^\s*[-*+]\s+', content, re.MULTILINE) or re.search(r'^\s*\d+\.\s+', content, re.MULTILINE):
            score += 5
        else:
            suggestions.append('Add bullet points or numbered lists')

        if re.search(r'\[.+?\]\(.+?\)', content):
            score += 5
        else:
            suggestions.append('Add internal/external links')

        paragraphs = [p for p in content.split('\n\n') if p.strip() and not p.strip().startswith('#')]
        if paragraphs:
            avg_para_words = sum(len(p.split()) for p in paragraphs) / len(paragraphs)
            if 50 <= avg_para_words <= 150:
                score += 5
            else:
                suggestions.append('Keep paragraphs 50-150 words')

        return jsonify({
            'success': True,
            'score': min(score, 100),
            'word_count': word_count,
            'keyword_density': round(keyword_density, 2) if keyword else 0,
            'heading_count': h2_count + h3_count,
            'issues': issues,
            'suggestions': suggestions,
            'grade': get_seo_grade(score)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-schema', methods=['POST'])
@api_login_required
@limiter.limit("20 per hour")
def api_generate_schema():
    if not current_user.can_use_ai():
        return jsonify({'error': 'AI request limit reached'}), 403

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
                "author": {
                    "@type": "Person",
                    "name": current_user.username
                },
                "datePublished": datetime.utcnow().strftime('%Y-%m-%d'),
                "dateModified": datetime.utcnow().strftime('%Y-%m-%d')
            }
        elif schema_type == 'Product':
            schema = {
                "@context": "https://schema.org",
                "@type": "Product",
                "name": title,
                "description": description,
                "brand": {
                    "@type": "Brand",
                    "name": data.get('brand', 'Your Brand')
                },
                "offers": {
                    "@type": "Offer",
                    "price": data.get('price', '0'),
                    "priceCurrency": data.get('currency', 'USD')
                }
            }
        elif schema_type == 'FAQ':
            schema = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": []
            }
        elif schema_type == 'Organization':
            schema = {
                "@context": "https://schema.org",
                "@type": "Organization",
                "name": title,
                "description": description,
                "url": data.get('url', ''),
                "logo": data.get('logo', '')
            }
        elif schema_type == 'LocalBusiness':
            schema = {
                "@context": "https://schema.org",
                "@type": "LocalBusiness",
                "name": title,
                "description": description,
                "address": {
                    "@type": "PostalAddress",
                    "streetAddress": data.get('street', ''),
                    "addressLocality": data.get('city', ''),
                    "addressRegion": data.get('state', ''),
                    "postalCode": data.get('zip', '')
                },
                "telephone": data.get('phone', '')
            }
        else:
            schema = {
                "@context": "https://schema.org",
                "@type": schema_type,
                "name": title,
                "description": description
            }

        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'schema': json.dumps(schema, indent=2)
        })
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
        content = data.get('content', '').strip()
        keyword = data.get('keyword', '').strip()

        if not title:
            return jsonify({'error': 'Title required'}), 400

        prompt = f"""Create an SEO-optimized meta description for:
Title: {title}
Keyword: {keyword}
Content snippet: {content[:200]}

Requirements:
- 150-160 characters
- Include keyword naturally
- Compelling call-to-action
- Accurate content summary

Provide ONLY the meta description text, nothing else."""

        result = call_openai(prompt, 100)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        meta_description = result['content'].strip().strip('"').strip("'")
        current_user.increment_ai_usage()

        meta_tags = {
            'title': title[:60],
            'description': meta_description[:160],
            'keywords': keyword,
            'og_title': title[:60],
            'og_description': meta_description[:160],
            'og_type': 'article',
            'twitter_card': 'summary_large_image',
            'twitter_title': title[:60],
            'twitter_description': meta_description[:160]
        }

        html = f"""<!-- Primary Meta Tags -->
<title>{meta_tags['title']}</title>
<meta name="title" content="{meta_tags['title']}">
<meta name="description" content="{meta_tags['description']}">
<meta name="keywords" content="{meta_tags['keywords']}">

<!-- Open Graph / Facebook -->
<meta property="og:type" content="{meta_tags['og_type']}">
<meta property="og:title" content="{meta_tags['og_title']}">
<meta property="og:description" content="{meta_tags['og_description']}">

<!-- Twitter -->
<meta property="twitter:card" content="{meta_tags['twitter_card']}">
<meta property="twitter:title" content="{meta_tags['twitter_title']}">
<meta property="twitter:description" content="{meta_tags['twitter_description']}">"""

        return jsonify({
            'success': True,
            'meta_tags': meta_tags,
            'html': html
        })
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
        image_context = data.get('context', '').strip()
        keyword = data.get('keyword', '').strip()
        image_name = data.get('image_name', '').strip()

        if not image_context and not image_name:
            return jsonify({'error': 'Image context or filename required'}), 400

        prompt = f"""Generate SEO-optimized alt text for an image.

Context: {image_context or 'Image from article'}
Filename: {image_name}
Target Keyword: {keyword}

Requirements:
- 125 characters max
- Descriptive and accurate
- Include keyword naturally if relevant
- Accessible for screen readers

Provide ONLY the alt text, nothing else."""

        result = call_openai(prompt, 50)

        if "error" in result:
            return jsonify({'error': result['error']}), 500

        alt_text = result['content'].strip().strip('"').strip("'")[:125]
        current_user.increment_ai_usage()

        return jsonify({
            'success': True,
            'alt_text': alt_text,
            'html': f'<img src="your-image.jpg" alt="{alt_text}">'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<int:content_id>/<format>')
@api_login_required
def api_export(content_id, format):
    try:
        content = Content.query.filter_by(id=content_id, user_id=current_user.id).first()
        if not content:
            return jsonify({'error': 'Content not found'}), 404

        allowed = current_user.get_limits()['export_formats']
        if format not in allowed:
            return jsonify({'error': f'{format} export not available in {current_user.tier} tier. Upgrade your plan!'}), 403

        safe_filename = re.sub(r'[^\w\s-]', '', content.title)[:50]

        if format == 'txt':
            output = BytesIO()
            output.write(f"{content.title}\n\n{content.content}".encode('utf-8'))
            output.seek(0)
            return send_file(output, mimetype='text/plain', as_attachment=True, download_name=f"{safe_filename}.txt")

        elif format == 'html':
            html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{content.title}</title></head>
<body><h1>{content.title}</h1>{markdown.markdown(content.content)}</body></html>"""
            output = BytesIO()
            output.write(html.encode('utf-8'))
            output.seek(0)
            return send_file(output, mimetype='text/html', as_attachment=True, download_name=f"{safe_filename}.html")

        elif format == 'md':
            output = BytesIO()
            output.write(f"# {content.title}\n\n{content.content}".encode('utf-8'))
            output.seek(0)
            return send_file(output, mimetype='text/markdown', as_attachment=True, download_name=f"{safe_filename}.md")

        elif format == 'docx':
            doc = Document()
            doc.add_heading(content.title, 0)
            for line in content.content.split('\n'):
                line = line.strip()
                if line.startswith('### '):
                    doc.add_heading(line[4:], 3)
                elif line.startswith('## '):
                    doc.add_heading(line[3:], 2)
                elif line.startswith('# '):
                    doc.add_heading(line[2:], 1)
                elif line:
                    doc.add_paragraph(line)
            output = BytesIO()
            doc.save(output)
            output.seek(0)
            return send_file(output,
                            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                            as_attachment=True,
                            download_name=f"{safe_filename}.docx")

        return jsonify({'error': 'Invalid format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('index'))

    users = User.query.order_by(User.created_at.desc()).all()
    total_content = Content.query.count()

    return render_template('admin.html', users=users, total_content=total_content)

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot deactivate yourself'}), 400

        user.is_active = not user.is_active
        db.session.commit()
        return jsonify({'success': True, 'is_active': user.is_active})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/user/<int:user_id>/tier', methods=['POST'])
@login_required
def admin_change_tier(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        user = User.query.get_or_404(user_id)
        tier = request.get_json().get('tier')

        if tier in ['free', 'pro', 'enterprise']:
            user.tier = tier
            db.session.commit()
            return jsonify({'success': True, 'tier': tier})

        return jsonify({'error': 'Invalid tier'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ============================================================================
# INITIALIZE DATABASE
# ============================================================================

with app.app_context():
    db.create_all()
    print("✅ Database initialized!")

# ============================================================================
# RUN APP
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug_mode = os.environ.get('FLASK_ENV', 'development') != 'production'
    
    print("\n" + "="*70)
    print("🚀 MySEOToolver V5 - COMPLETE AI-Powered SEO Platform")
    print("="*70)
    print(f"✅ Database: {'PostgreSQL (Railway)' if os.environ.get('DATABASE_URL') else 'SQLite (Local)'}")
    print(f"✅ OpenAI: {'Connected (' + openai_api_key[:15] + '...)' if client else '⚠️  Set OPENAI_API_KEY in Railway Variables'}")
    print(f"✅ Server: http://0.0.0.0:{port}")
    print(f"✅ Environment: {'Production' if not debug_mode else 'Development'}")
    print("="*70 + "\n")

    app.run(debug=debug_mode, host='0.0.0.0', port=port)
