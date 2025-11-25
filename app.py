from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import re, os, requests, base64, json, validators
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from io import BytesIO

# ==========================================
# 1. CONFIGURATION
# ==========================================
load_dotenv()
app = Flask(__name__)

# Database Config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# OpenAI Client
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

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
    
    # Cascade Delete
    contents = db.relationship('Content', backref='author', lazy=True, cascade="all, delete-orphan")
    
    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def get_limits(self):
        limits = {'free': 50, 'pro': 500, 'enterprise': 9999}
        return {'ai_requests_per_month': limits.get(self.tier, 50)}

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
# 3. PERMISSION SETTINGS
# ==========================================
PRO_TOOLS = [
    'competitor-analyzer', 'image-seo', 'sitemap-generator', 
    'robots-generator', 'schema-generator', 'social-posts', 
    'youtube-script', 'faq-schema', 'alt-text-generator',
    'serp-analysis', 'plagiarism-checker', 'meta-tags'
]

# ==========================================
# 4. CORE PAGE ROUTES
# ==========================================
@app.route('/')
def landing(): 
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

app.add_url_rule('/', endpoint='home', view_func=landing)
app.add_url_rule('/', endpoint='index', view_func=landing)

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
def pricing(): 
    return render_template('pricing.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# ==========================================
# 5. AUTHENTICATION ROUTES
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        
        if user and user.check_password(data.get('password')):
            if not user.is_active:
                return jsonify({'error': 'Account is banned. Contact support.'}), 403
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
            if not data.get('username') or len(data.get('username')) < 3:
                return jsonify({'error': 'Username required (min 3 chars)'}), 400
            if User.query.filter_by(username=data.get('username')).first():
                return jsonify({'error': 'Username taken'}), 400
            if User.query.filter_by(email=data.get('email').lower()).first(): 
                return jsonify({'error': 'Email already exists'}), 400
            
            hashed = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
            user = User(username=data.get('username'), email=data.get('email').lower(), password_hash=hashed)
            
            if User.query.count() == 0: user.is_admin = True
            
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return jsonify({'success': True, 'redirect': '/dashboard'})
        except Exception as e: 
            return jsonify({'error': str(e)}), 500
            
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout(): 
    logout_user() 
    return redirect('/')

# ==========================================
# 6. ADMIN ROUTES
# ==========================================
@app.route('/admin')
@login_required
def admin():
    if not getattr(current_user, 'is_admin', False): 
        return redirect('/dashboard')
    users = User.query.order_by(User.id.desc()).all()
    total_content = Content.query.count()
    return render_template('admin.html', users=users, total_content=total_content)

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: return jsonify({'error': 'Cannot ban yourself'}), 400
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True, 'status': user.is_active})

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: return jsonify({'error': 'Cannot delete yourself'}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

# ==========================================
# 7. TOOL ROUTES
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    all_tools = PRO_TOOLS + ['keyword-research', 'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 'headline-analyzer', 'internal-linking', 'readability-checker']
    
    if tool_name not in all_tools:
        return "Tool not found", 404

    if tool_name in PRO_TOOLS and current_user.tier == 'free':
        flash("Upgrade to Pro to use this tool!", "warning")
        return redirect('/pricing')
        
    return render_template(f'{tool_name.replace("-", "_")}.html')

tool_list = [
    'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
    'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
    'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
    'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
    'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis'
]

for t in tool_list:
    app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t:
        app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))


# ==========================================
# 8. API ENDPOINTS
# ==========================================

# --- Save Content ---
@app.route('/api/save-content', methods=['POST'])
@login_required
def api_save_content():
    d = request.get_json()
    try:
        if d.get('id'):
            c = Content.query.get(d.get('id'))
            if c and c.user_id == current_user.id:
                c.title = d.get('title'); c.content = d.get('content'); c.html_content = d.get('html_content')
                c.keyword = d.get('keyword'); c.word_count = len(d.get('content', '').split())
                # Simple score fallback
                score = 0
                if c.word_count > 800: score += 40
                if c.keyword and c.keyword.lower() in c.title.lower(): score += 30
                c.seo_score = min(score + 30, 100)
                
                db.session.commit()
                return jsonify({'success': True, 'id': c.id})
        
        new_c = Content(
            user_id=current_user.id, title=d.get('title', 'Untitled'), 
            keyword=d.get('keyword'), content=d.get('content'), 
            html_content=d.get('html_content'), word_count=len(d.get('content', '').split())
        )
        db.session.add(new_c)
        current_user.content_count += 1
        db.session.commit()
        return jsonify({'success': True, 'id': new_c.id})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- Generate AI Content ---
@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    limits = current_user.get_limits()
    if current_user.ai_requests_this_month >= limits['ai_requests_per_month']:
        return jsonify({'error': 'Monthly Limit Reached. Upgrade to Pro!'}), 403

    try:
        data = request.get_json()
        sys_prompt = "You are a helpful SEO expert writer."
        if data.get('mode') == 'human': sys_prompt = "You are an opinionated human writer. Write at an 8th-grade level."
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": sys_prompt}, {"role": "user", "content": data.get('keyword')}],
            max_tokens=1500
        )
        text = res.choices[0].message.content
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({'success': True, 'content': text, 'html_content': markdown.markdown(text)})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- SEO Terms Generator ---
@app.route('/api/generate-seo-terms', methods=['POST'])
@login_required
def api_generate_seo_terms():
    try:
        data = request.get_json()
        keyword = data.get('keyword')
        if not keyword: return jsonify({'error': 'Keyword missing'}), 400
        
        prompt = f"List 20 single-word or two-word semantic keywords (LSI) that are essential for an in-depth article about '{keyword}'. Return ONLY a JSON array of strings. Example: ['term1', 'term2']"
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are an SEO expert JSON generator."}, {"role": "user", "content": prompt}],
            max_tokens=500
        )
        
        content = res.choices[0].message.content.replace('```json', '').replace('```', '').strip()
        terms = json.loads(content)
        
        return jsonify({'success': True, 'terms': terms})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- PAA Questions Generator ---
@app.route('/api/generate-questions', methods=['POST'])
@login_required
def api_generate_questions():
    try:
        data = request.get_json()
        keyword = data.get('keyword')
        if not keyword: return jsonify({'error': 'Keyword missing'}), 400
        
        prompt = f"List 5 common 'People Also Ask' questions related to '{keyword}'. Return ONLY a JSON array of strings."
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are an SEO expert JSON generator."}, {"role": "user", "content": prompt}],
            max_tokens=500
        )
        
        content = res.choices[0].message.content.replace('```json', '').replace('```', '').strip()
        questions = json.loads(content)
        
        return jsonify({'success': True, 'questions': questions})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- Internal Link Suggester ---
@app.route('/api/suggest-internal-links', methods=['POST'])
@login_required
def api_suggest_internal_links():
    try:
        data = request.get_json()
        search = data.get('keyword', '')
        current_id = data.get('current_id')
        
        # Search for other posts by user where title is similar
        query = Content.query.filter(
            Content.user_id == current_user.id,
            Content.title.ilike(f'%{search}%')
        )
        if current_id:
            try:
                query = query.filter(Content.id != int(current_id))
            except: pass
        results = query.limit(5).all()
        
        # Fallback
        if not results:
            base_query = Content.query.filter(Content.user_id == current_user.id)
            if current_id:
                try:
                    base_query = base_query.filter(Content.id != int(current_id))
                except: pass
            results = base_query.order_by(Content.updated_at.desc()).limit(5).all()

        links = [{'id': c.id, 'title': c.title} for c in results]
        return jsonify({'success': True, 'links': links})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- READABILITY HELPER & API ---
def count_syllables(word):
    word = word.lower()
    count = 0
    vowels = "aeiouy"
    if word[0] in vowels: count += 1
    for i in range(1, len(word)):
        if word[i] in vowels and word[i - 1] not in vowels:
            count += 1
    if word.endswith("e"): count -= 1
    if count == 0: count += 1
    return count

@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_check_readability():
    try:
        data = request.get_json()
        text = data.get('content', '')
        if not text: return jsonify({'error': 'No text provided'}), 400

        sentences = re.split(r'[.!?]+', text)
        sentences = [s for s in sentences if len(s.strip()) > 0]
        num_sentences = len(sentences) or 1
        
        words = re.findall(r'\b\w+\b', text)
        num_words = len(words) or 1
        
        num_syllables = sum(count_syllables(w) for w in words)

        # Flesch-Kincaid Grade Level
        score = 0.39 * (num_words / num_sentences) + 11.8 * (num_syllables / num_words) - 15.59
        grade = round(score, 1)

        difficulty = "Very Easy"
        color = "success"
        if grade > 6: difficulty = "Easy (6th Grade)"
        if grade > 8: difficulty = "Standard (8th Grade)"
        if grade > 10: 
            difficulty = "Difficult (10th Grade)"
            color = "warning"
        if grade > 12: 
            difficulty = "Very Difficult (College)"
            color = "danger"

        return jsonify({
            'success': True,
            'stats': {
                'grade': grade,
                'difficulty': difficulty,
                'sentences': num_sentences,
                'words': num_words,
                'color': color
            }
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- SCHEMA GENERATOR API ---
@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_generate_schema():
    try:
        d = request.get_json()
        schema_type = d.get('type')
        result = {}
        
        if schema_type == 'article':
            result = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": d.get('headline'),
                "image": [d.get('image')],
                "author": {"@type": "Person", "name": d.get('author')},
                "publisher": {"@type": "Organization", "name": "MySEO King"},
                "datePublished": datetime.now().strftime('%Y-%m-%d')
            }
        elif schema_type == 'faq':
            pairs = d.get('faq_content', '').split('\n\n')
            questions = []
            for p in pairs:
                parts = p.split('\n')
                if len(parts) >= 2:
                    questions.append({
                        "@type": "Question",
                        "name": parts[0],
                        "acceptedAnswer": {"@type": "Answer", "text": parts[1]}
                    })
            result = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": questions
            }

        return jsonify({'success': True, 'json': json.dumps(result, indent=4)})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- Keyword Clusters ---
@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_generate_clusters():
    if current_user.tier == 'free': return jsonify({'error': 'Pro Feature'}), 403
    try:
        data = request.get_json()
        prompt = f"Generate a keyword cluster strategy for: '{data.get('keyword')}'. Create 4 clusters. Output strictly JSON: [{{'name': '...', 'keywords': ['...']}}]"
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are a JSON generator."}, {"role": "user", "content": prompt}],
            max_tokens=1000
        )
        content = res.choices[0].message.content.replace('```json', '').replace('```', '').strip()
        clusters = json.loads(content)
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'clusters': clusters})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- Competitor Analysis ---
@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_analyze_competitor():
    if current_user.tier == 'free': return jsonify({'error': 'Pro Feature'}), 403
    try:
        url = request.get_json().get('url')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 406: return jsonify({'error': 'Blocked by WAF'}), 406
        
        soup = BeautifulSoup(r.content, 'html.parser')
        images = [{'src': urljoin(url, i.get('src')), 'alt': i.get('alt', '')} for i in soup.find_all('img') if i.get('src')]
        for s in soup(["script", "style"]): s.extract()
        
        return jsonify({'success': True, 'analysis': {
            'title': soup.title.string if soup.title else "No Title",
            'h1_tags': [h.text.strip() for h in soup.find_all('h1')],
            'word_count': len(soup.get_text().split()),
            'images': images, 'total_images': len(images)
        }})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- Delete Content ---
@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id:
        db.session.delete(c)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Auth'}), 403

# --- Export ---
@app.route('/api/export/<int:id>/<fmt>')
@login_required
def api_export(id, fmt):
    c = Content.query.get_or_404(id)
    if c.user_id != current_user.id: return "Auth Error", 403
    data = c.content if fmt == 'txt' else c.html_content
    mime = 'text/plain' if fmt == 'txt' else 'text/html'
    filename = re.sub(r'[\\/*?:"<>|]', "", c.title) or "document"
    return send_file(BytesIO(data.encode()), mimetype=mime, as_attachment=True, download_name=f"{filename}.{fmt}")

# --- Sitemap Gen ---
@app.route('/api/generate-sitemap', methods=['POST'])
@login_required
def api_generate_sitemap():
    if current_user.tier == 'free': return jsonify({'error': 'Pro Feature'}), 403
    try:
        url = request.get_json().get('url')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        r = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
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

# --- Robots Gen ---
@app.route('/api/generate-robots', methods=['POST'])
@login_required
def api_generate_robots():
    d = request.get_json()
    c = f"User-agent: {d.get('userAgent', '*')}\n"
    if d.get('allow'): c += f"Allow: {d.get('allow')}\n"
    if d.get('disallow'): c += f"Disallow: {d.get('disallow')}\n"
    if d.get('sitemap'): c += f"\nSitemap: {d.get('sitemap')}"
    return jsonify({'success': True, 'content': c})

# ==========================================
# 9. INITIALIZATION
# ==========================================
with app.app_context():
    try: db.create_all()
    except: pass

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
