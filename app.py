from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
import re, os, requests, base64, json, validators, csv
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from io import BytesIO, StringIO
from sqlalchemy import text
from youtube_transcript_api import YouTubeTranscriptApi

# ==========================================
# 1. CONFIGURATION & GLOBAL VARS
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

# --- GLOBAL TOOL LIST (Defined at top to prevent NameError) ---
TOOL_LIST = [
    'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
    'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
    'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
    'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
    'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis',
    'youtube-to-blog'
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

# --- TECHNICAL SEO ROUTES ---
@app.route('/robots.txt')
def robots_txt():
    lines = ["User-agent: *", "Disallow: /dashboard", "Disallow: /editor", f"Sitemap: {request.url_root}sitemap.xml"]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    pages = ['/', '/pricing', '/login', '/signup']
    
    # Use the global TOOL_LIST here
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

@app.route('/payment/success/<plan_name>')
@login_required
def payment_success(plan_name):
    if plan_name == 'pro': current_user.tier = 'pro king'
    elif plan_name == 'enterprise': current_user.tier = 'enterprise'
    db.session.commit()
    return redirect('/dashboard')

# ==========================================
# 6. DYNAMIC TOOL ROUTER
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    return render_template(f'{tool_name.replace("-", "_")}.html')

# Register URLs using global list
for t in TOOL_LIST:
    app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t: app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))

# ==========================================
# 7. API ENDPOINTS (AI & TOOLS)
# ==========================================

@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached.'}), 403
    data = request.get_json(); video_url = data.get('url')
    try:
        vid_id = video_url.split("v=")[1].split("&")[0] if "v=" in video_url else video_url.split("youtu.be/")[1].split("?")[0]
        # Robust Transcript Fetch
        try:
            t_list = YouTubeTranscriptApi.list_transcripts(vid_id)
            try: transcript = t_list.find_transcript(['en','en-US'])
            except: transcript = t_list.find_generated_transcript(['en'])
            text_data = " ".join([t['text'] for t in transcript.fetch()])
        except: return jsonify({'error': 'No English captions found.'}), 400
        
        # AI Process
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"system","content":"Blog Writer"},{"role":"user","content":f"Turn into blog: {text_data[:15000]}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached.'}), 403
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"system","content":"SEO Expert"},{"role":"user","content":request.get_json().get('keyword')}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
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

@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id: db.session.delete(c); db.session.commit()
    return jsonify({'success': True})

# --- Helper APIs ---
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
def api_readability(): return jsonify({'success':True, 'stats': {'grade': 8, 'difficulty': 'Good', 'sentences': 10, 'words': 100, 'color': 'success'}})

@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_schema(): return jsonify({'success':True, 'json': json.dumps({"@context":"https://schema.org","@type":"Article","headline":request.get_json().get('headline')}, indent=4)})

@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_competitor():
    r = requests.get(request.get_json().get('url'), headers={'User-Agent':'Mozilla/5.0'})
    s = BeautifulSoup(r.content, 'html.parser')
    return jsonify({'success':True, 'analysis': {'title':s.title.string, 'word_count':len(s.get_text().split()), 'h1_tags':[h.text for h in s.find_all('h1')], 'images':[], 'total_images':0}})

@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_clusters():
    res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"Clusters for {request.get_json().get('keyword')} as JSON"}])
    return jsonify({'success':True, 'clusters': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})

@app.route('/test-email')
def test_email():
    try:
        msg = Message("Test", recipients=['dilawarahsanrizvi7@gmail.com']); msg.body = "Working"; mail.send(msg)
        return "Sent"
    except Exception as e: return f"Err: {e}"

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
