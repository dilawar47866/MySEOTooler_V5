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
# 1. CONFIGURATION
# ==========================================
load_dotenv()
app = Flask(__name__)

# Database Config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

# Email Config (Hostinger)
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
# 3. PERMISSION SETTINGS
# ==========================================
PRO_TOOLS = [
    'competitor-analyzer', 'image-seo', 'sitemap-generator', 
    'robots-generator', 'schema-generator', 'social-posts', 
    'youtube-script', 'faq-schema', 'alt-text-generator',
    'serp-analysis', 'plagiarism-checker', 'meta-tags', 'youtube-to-blog'
]

# ==========================================
# 4. CORE PAGE ROUTES
# ==========================================
@app.route('/')
def landing(): 
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
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
def pricing(): return render_template('pricing.html')

@app.route('/profile')
@login_required
def profile(): return render_template('profile.html')

# --- TECHNICAL SEO ROUTES ---
@app.route('/robots.txt')
def robots_txt():
    lines = [
        "User-agent: *",
        "Disallow: /dashboard",
        "Disallow: /editor",
        "Disallow: /profile",
        f"Sitemap: {request.url_root}sitemap.xml"
    ]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    pages = ['/', '/pricing', '/login', '/signup']
    tool_list = [
        'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
        'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
        'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
        'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
        'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis',
        'youtube-to-blog'
    ]
    for slug in tool_list:
        pages.append(f'/tool/{slug}')

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += f'  <url>\n    <loc>{base_url}{page}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>{0.8 if page == "/" else 0.6}</priority>\n  </url>\n'
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}

# ==========================================
# 5. AUTHENTICATION ROUTES
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        if user and user.check_password(data.get('password')):
            if not user.is_active: return jsonify({'error': 'Account is banned.'}), 403
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
            if not data.get('username'): return jsonify({'error': 'Username required'}), 400
            if User.query.filter_by(email=data.get('email').lower()).first(): return jsonify({'error': 'Email exists'}), 400
            
            hashed = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
            user = User(username=data.get('username'), email=data.get('email').lower(), password_hash=hashed)
            if User.query.count() == 0: user.is_admin = True
            
            db.session.add(user); db.session.commit(); login_user(user)

            try:
                msg = Message("Welcome to MySEO King! 👑", recipients=[user.email])
                msg.body = f"Hi {user.username},\n\nWelcome to the #1 AI SEO Tool. Start creating now!\n\nCheers,\nMySEO King Team"
                mail.send(msg)
            except: pass

            return jsonify({'success': True, 'redirect': '/dashboard'})
        except Exception as e: return jsonify({'error': str(e)}), 500
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect('/')

# ==========================================
# 6. ADMIN & PAYMENT
# ==========================================
@app.route('/admin')
@login_required
def admin():
    if not getattr(current_user, 'is_admin', False): return redirect('/dashboard')
    users = User.query.order_by(User.id.desc()).all()
    total_content = Content.query.count()
    return render_template('admin.html', users=users, total_content=total_content)

@app.route('/admin/export-users')
@login_required
def admin_export_users():
    if not getattr(current_user, 'is_admin', False): return "Unauthorized", 403
    si = StringIO(); cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Email', 'Tier', 'Join Date', 'Usage'])
    for u in User.query.all(): cw.writerow([u.id, u.username, u.email, u.tier, u.last_reset_date, u.ai_requests_this_month])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=users.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: return jsonify({'error': 'Cannot ban self'}), 400
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not getattr(current_user, 'is_admin', False): return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: return jsonify({'error': 'Cannot delete self'}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/payment/success/<plan_name>')
@login_required
def payment_success(plan_name):
    if plan_name == 'pro': current_user.tier = 'pro king'
    elif plan_name == 'enterprise': current_user.tier = 'enterprise'
    db.session.commit()
    flash(f"Upgraded to {plan_name.upper()}!", "success")
    return redirect('/dashboard')

# ==========================================
# 7. TOOL ROUTES
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    return render_template(f'{tool_name.replace("-", "_")}.html')

for t in tool_list:
    app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t: app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))

# ==========================================
# 8. API ENDPOINTS
# ==========================================

# --- YOUTUBE TO BLOG API (ROBUST) ---
@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached.'}), 403

    data = request.get_json()
    video_url = data.get('url')
    
    try:
        # 1. Extract Video ID
        video_id = ""
        if "youtu.be/" in video_url: video_id = video_url.split("youtu.be/")[1].split("?")[0]
        elif "v=" in video_url: video_id = video_url.split("v=")[1].split("&")[0]
        elif "shorts/" in video_url: video_id = video_url.split("shorts/")[1].split("?")[0]
            
        if not video_id: return jsonify({'error': 'Invalid URL'}), 400

        # 2. ROBUST FETCH STRATEGY
        try:
            transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)
            
            # Attempt 1: Find specific English
            try:
                transcript = transcript_list.find_transcript(['en', 'en-US', 'en-GB'])
            except:
                # Attempt 2: Find ANY available transcript and translate it
                transcript = None
                for t in transcript_list:
                    if t.is_translatable:
                        transcript = t.translate('en')
                        break
                    # If not translatable but exists, just use it (OpenAI can handle broken English)
                    transcript = t 
                    break
            
            if not transcript: raise Exception("No transcripts available")
            
            transcript_data = transcript.fetch()
            full_text = " ".join([t['text'] for t in transcript_data])
            
        except Exception:
            # Attempt 3: Old fallback method
            try:
                transcript_data = YouTubeTranscriptApi.get_transcript(video_id)
                full_text = " ".join([t['text'] for t in transcript_data])
            except Exception as final_err:
                return jsonify({'error': f"Could not retrieve transcript. The video might not have captions. Error: {str(final_err)}"}), 400

        # 3. Truncate
        full_text = full_text[:15000] 

        # 4. OpenAI Process
        prompt = f"Convert this YouTube transcript into a blog post with H1, H2, bullet points. Transcript: {full_text}"
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are a blog writer."}, {"role": "user", "content": prompt}],
            max_tokens=2000
        )
        
        blog_content = res.choices[0].message.content
        current_user.ai_requests_this_month += 1
        db.session.commit()

        return jsonify({'success': True, 'content': blog_content, 'html': markdown.markdown(blog_content)})

    except Exception as e: return jsonify({'error': f"System Error: {str(e)}"}), 500

# --- GENERIC API ---
@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached.'}), 403
    try:
        data = request.get_json()
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You are an SEO expert."}, {"role": "user", "content": data.get('keyword')}],
            max_tokens=1500
        )
        text = res.choices[0].message.content
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': text, 'html_content': markdown.markdown(text)})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- SAVE CONTENT ---
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

# --- OTHER APIS ---
@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id: db.session.delete(c); db.session.commit()
    return jsonify({'success': True})

# --- SEO TOOLS ---
@app.route('/api/generate-seo-terms', methods=['POST'])
@login_required
def api_generate_seo_terms():
    try:
        data = request.get_json(); keyword = data.get('keyword')
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON gen"},{"role":"user","content":f"List 20 LSI keywords for '{keyword}' as JSON array"}])
        return jsonify({'success': True, 'terms': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-questions', methods=['POST'])
@login_required
def api_generate_questions():
    try:
        data = request.get_json(); keyword = data.get('keyword')
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON gen"},{"role":"user","content":f"List 5 PAA questions for '{keyword}' as JSON array"}])
        return jsonify({'success': True, 'questions': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/suggest-internal-links', methods=['POST'])
@login_required
def api_suggest_internal_links():
    try:
        data = request.get_json(); search = data.get('keyword', '')
        results = Content.query.filter(Content.user_id==current_user.id, Content.title.ilike(f'%{search}%')).limit(5).all()
        if not results: results = Content.query.filter(Content.user_id==current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
        return jsonify({'success': True, 'links': [{'id':c.id, 'title':c.title} for c in results]})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- READABILITY & SCHEMA ---
@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_check_readability():
    return jsonify({'success': True, 'stats': {'grade': 8, 'difficulty': 'Standard', 'sentences': 10, 'words': 100, 'color': 'success'}})

@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_generate_schema():
    d = request.get_json()
    return jsonify({'success': True, 'json': json.dumps({"@context":"https://schema.org","@type":d.get('type',"Article"),"headline":d.get('headline',"")}, indent=4)})

# --- COMPETITOR & CLUSTERS ---
@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_analyze_competitor():
    try:
        url = request.get_json().get('url')
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(r.content, 'html.parser')
        return jsonify({'success': True, 'analysis': {'title': soup.title.string, 'word_count': len(soup.get_text().split()), 'h1_tags': [h.text for h in soup.find_all('h1')], 'images': [], 'total_images': 0}})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_generate_clusters():
    try:
        data = request.get_json()
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON gen"},{"role":"user","content":f"Keyword clusters for '{data.get('keyword')}' as JSON"}])
        return jsonify({'success': True, 'clusters': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- DEBUGGING ---
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

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))
