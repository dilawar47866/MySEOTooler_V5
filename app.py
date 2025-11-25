from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import re, os, requests, base64, json, validators
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from io import BytesIO

# --- CONFIG ---
load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    tier = db.Column(db.String(20), default='free')
    content_count = db.Column(db.Integer, default=0)
    ai_requests_this_month = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)
    def get_limits(self):
        limits = {'free': 50, 'pro': 500, 'enterprise': 9999}
        return {'ai_requests_per_month': limits.get(self.tier, 50)}

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    keyword = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    html_content = db.Column(db.Text)
    seo_score = db.Column(db.Integer, default=0)
    word_count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- ROUTES ---
@app.route('/')
def landing(): return redirect(url_for('dashboard')) if current_user.is_authenticated else render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
    total = Content.query.filter_by(user_id=current_user.id).count()
    words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    return render_template('index.html', recent_content=recent, total_content=total, total_words=words, limits=current_user.get_limits())

@app.route('/editor')
@login_required
def editor():
    c = Content.query.filter_by(id=request.args.get('id'), user_id=current_user.id).first() if request.args.get('id') else None
    return render_template('editor.html', content=c)

@app.route('/pricing')
def pricing(): return render_template('pricing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        if user and user.check_password(data.get('password')):
            login_user(user)
            return jsonify({'success': True, 'redirect': '/dashboard'})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect('/')

# --- TOOL ROUTES (ALL INCLUDED) ---
tools = ['content-library', 'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
         'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
         'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
         'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
         'faq-schema', 'youtube-script']

for tool in tools:
    app.add_url_rule(f'/{tool}', tool.replace('-', '_'), lambda tool=tool: render_template(f'{tool.replace("-", "_")}.html'))

# --- API ENDPOINTS ---

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
                # Rough score calc
                score = 0
                if c.word_count > 800: score += 40
                if c.keyword and c.keyword.lower() in c.title.lower(): score += 30
                c.seo_score = min(score + 30, 100)
                db.session.commit()
                return jsonify({'success': True, 'id': c.id})
        
        # Create New
        new_c = Content(user_id=current_user.id, title=d.get('title', 'Untitled'), 
                        keyword=d.get('keyword'), content=d.get('content'), 
                        html_content=d.get('html_content'), word_count=len(d.get('content', '').split()))
        db.session.add(new_c)
        current_user.content_count += 1
        db.session.commit()
        return jsonify({'success': True, 'id': new_c.id})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    try:
        data = request.get_json()
        sys_prompt = "You are a helpful SEO expert writer."
        if data.get('mode') == 'human': sys_prompt = "You are an opinionated human writer. Use burstiness."
        
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

@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_analyze_competitor():
    try:
        url = request.get_json().get('url')
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

@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id:
        db.session.delete(c)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Auth'}), 403

@app.route('/api/export/<int:id>/<fmt>')
@login_required
def api_export(id, fmt):
    c = Content.query.get_or_404(id)
    if c.user_id != current_user.id: return "Auth Error", 403
    
    data = c.content if fmt == 'txt' else c.html_content
    mime = 'text/plain' if fmt == 'txt' else 'text/html'
    return send_file(BytesIO(data.encode()), mimetype=mime, as_attachment=True, download_name=f"{c.title}.{fmt}")

# --- INIT ---
with app.app_context():
    try: db.create_all()
    except: pass

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
