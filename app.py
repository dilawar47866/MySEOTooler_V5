from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
# from flask_limiter import Limiter # Removed: Imported but not used in the provided code
# from flask_limiter.util import get_remote_address # Removed: Imported but not used
from flask_wtf.csrf import CSRFProtect # ADDED: For security (CSRF protection)
from datetime import datetime
from sqlalchemy import event # ADDED: For database event listeners (optional, but good practice)
from sqlalchemy.engine import Engine # ADDED: For database engine type
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

# --- Database Config ---
# FIX: Ensure a fallback URI is always available
database_url = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db')
# FIX: Standardize postgres:// to postgresql:// for compatibility with SQLAlchemy >= 1.4
app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# FIX: SECRET_KEY must be set for CSRF and sessions
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me-REPLACE-IN-PROD') 

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ADDED: CSRF Protection
csrf = CSRFProtect(app)

# OpenAI Client
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Optional: SQLite performance tweak (good practice for SQLite)
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

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
    
    # Cascade Delete: If user is deleted, delete their content too
    contents = db.relationship('Content', backref='author', lazy=True, cascade="all, delete-orphan")
    
    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password)
    
    # NEW FEATURE: Logic to handle monthly reset of AI requests
    def reset_ai_requests_if_new_month(self):
        now = datetime.utcnow()
        if self.last_reset_date.month != now.month or self.last_reset_date.year != now.year:
            self.ai_requests_this_month = 0
            self.last_reset_date = now
            db.session.commit() # Commit the reset
            
    def get_limits(self):
        # Ensure reset check runs every time limits are accessed
        self.reset_ai_requests_if_new_month() 
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
# 3. PERMISSION SETTINGS (Feature Gating)
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
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Call get_limits to ensure the monthly count is reset if needed
    limits = current_user.get_limits() 
    
    recent = Content.query.filter_by(user_id=current_user.id).order_by(Content.updated_at.desc()).limit(5).all()
    total = Content.query.filter_by(user_id=current_user.id).count()
    words = db.session.query(db.func.sum(Content.word_count)).filter_by(user_id=current_user.id).scalar() or 0
    
    avg_score = 0
    scores = [c.seo_score for c in Content.query.filter_by(user_id=current_user.id).all()]
    if scores: avg_score = sum(scores) / len(scores)

    return render_template('index.html', recent_content=recent, total_content=total, 
                           total_words=words, avg_score=round(avg_score, 1), 
                           limits=limits)

@app.route('/editor')
@login_required
def editor():
    c = Content.query.filter_by(id=request.args.get('id'), user_id=current_user.id).first() if request.args.get('id') else None
    return render_template('editor.html', content=c)

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
        # NOTE: JSON endpoint, so CSRF protection needs to be handled client-side 
        # (e.g., sending the token in the AJAX header), or disabled for this endpoint if 
        # it is exclusively API. Assuming API-only for login/signup data submission.
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').lower()
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
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
            
            username = data.get('username')
            email = data.get('email', '').lower()
            password = data.get('password')

            # Validations
            if not username or len(username) < 3:
                return jsonify({'error': 'Username required (min 3 chars)'}), 400
            if not password or len(password) < 6:
                 return jsonify({'error': 'Password required (min 6 chars)'}), 400
            if User.query.filter_by(username=username).first():
                return jsonify({'error': 'Username taken'}), 400
            if User.query.filter_by(email=email).first(): 
                return jsonify({'error': 'Email already exists'}), 400
            
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password_hash=hashed)
            
            # First user becomes Admin
            if User.query.count() == 0: user.is_admin = True
            
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return jsonify({'success': True, 'redirect': '/dashboard'})
        except Exception as e: 
            # Log the error for debugging
            app.logger.error(f"Signup error: {e}")
            return jsonify({'error': 'An internal error occurred during signup.'}), 500
            
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
        flash("Unauthorized access.", "danger")
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
    
    # DB Cascade handles content deletion
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

# ==========================================
# 7. TOOL ROUTES (With Security)
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    all_tools = PRO_TOOLS + ['keyword-research', 'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 'headline-analyzer', 'internal-linking', 'readability-checker']
    
    if tool_name not in all_tools:
        # ADDED: Improved error reporting for missing tool
        flash(f"Tool '{tool_name}' not found.", "danger")
        return redirect(url_for('dashboard'))

    # ENFORCE PRO LIMITS
    if tool_name in PRO_TOOLS and current_user.tier == 'free':
        flash("Upgrade to Pro to use this tool!", "warning")
        return redirect('/pricing')
        
    # File naming convention: tool-name -> tool_name.html
    return render_template(f'{tool_name.replace("-", "_")}.html')

# Register URL rules for all tools
tool_list = [
    'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
    'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
    'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
    'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
    'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis'
]

for t in tool_list:
    # FIX: Registered endpoint with underscores (replace - with _) so {{ url_for('tool_name') }} works
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
        # Input validation
        if not d.get('title') or not d.get('content'):
            return jsonify({'error': 'Title and content are required.'}), 400
            
        content_text = d.get('content', '')
        word_count = len(content_text.split())
        
        # Simple SEO Score Logic (As in original code)
        score = 0
        if word_count > 800: score += 40
        if d.get('keyword') and d.get('keyword').lower() in d.get('title', '').lower(): score += 30
        seo_score = min(score + 30, 100) # Max 100

        if d.get('id'):
            c = Content.query.get(d.get('id'))
            if c and c.user_id == current_user.id:
                c.title = d.get('title')
                c.content = content_text
                c.html_content = d.get('html_content')
                c.keyword = d.get('keyword')
                c.word_count = word_count
                c.seo_score = seo_score
                
                db.session.commit()
                return jsonify({'success': True, 'id': c.id})
            return jsonify({'error': 'Content not found or unauthorized'}), 404
        
        new_c = Content(
            user_id=current_user.id, 
            title=d.get('title', 'Untitled'), 
            keyword=d.get('keyword'), 
            content=content_text, 
            html_content=d.get('html_content'), 
            word_count=word_count,
            seo_score=seo_score
        )
        db.session.add(new_c)
        current_user.content_count += 1
        db.session.commit()
        return jsonify({'success': True, 'id': new_c.id})
    except Exception as e: 
        app.logger.error(f"Save Content Error: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500

# --- Generate AI Content ---
@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    # Call get_limits to ensure the monthly count is reset if needed BEFORE checking the limit
    limits = current_user.get_limits()
    if current_user.ai_requests_this_month >= limits['ai_requests_per_month']:
        return jsonify({'error': f"Monthly Limit Reached ({current_user.ai_requests_this_month}/{limits['ai_requests_per_month']}). Upgrade to Pro!"}), 403

    try:
        data = request.get_json()
        keyword = data.get('keyword')
        if not keyword:
             return jsonify({'error': 'Keyword is required for content generation.'}), 400
             
        sys_prompt = "You are a helpful SEO expert writer."
        if data.get('mode') == 'human': sys_prompt = "You are an opinionated human writer. Write at an 8th-grade level."
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": sys_prompt}, {"role": "user", "content": keyword}],
            max_tokens=1500
        )
        text = res.choices[0].message.content
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({'success': True, 'content': text, 'html_content': markdown.markdown(text)})
    except Exception as e: 
        app.logger.error(f"AI Generation Error: {e}")
        return jsonify({'error': 'AI Generation Failed. Please try again.'}), 500

# --- Keyword Clusters ---
@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_generate_clusters():
    if current_user.tier == 'free': return jsonify({'error': 'Pro Feature'}), 403
    # Reset check
    current_user.reset_ai_requests_if_new_month()
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Monthly AI limit reached.'}), 403
        
    try:
        data = request.get_json()
        prompt = f"Generate a keyword cluster strategy for: '{data.get('keyword')}'. Create 4 clusters. Output strictly JSON: [{{'name': '...', 'keywords': ['...']}}]"
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            # Requesting JSON response is a good practice for this type of API
            response_format={"type": "json_object"}, 
            messages=[{"role": "system", "content": "You are a JSON generator. Do not include any text outside the JSON object."}, {"role": "user", "content": prompt}],
            max_tokens=1000
        )
        # Content is now expected to be a strict JSON string
        content = res.choices[0].message.content.strip()
        clusters = json.loads(content)
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'clusters': clusters})
    except json.JSONDecodeError as e:
        app.logger.error(f"JSON Decode Error in Clusters: {e} - Content: {content}")
        return jsonify({'error': 'Failed to parse AI response as JSON.'}), 500
    except Exception as e: 
        app.logger.error(f"Cluster Generation Error: {e}")
        return jsonify({'error': 'An error occurred during cluster generation.'}), 500

# --- Competitor Analysis ---
@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_analyze_competitor():
    if current_user.tier == 'free': return jsonify({'error': 'Pro Feature'}), 403
    try:
        url = request.get_json().get('url')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        
        # Use a more generic user-agent to avoid immediate blocking
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; MySEOTool/1.0; +http://myseotool.com)'} 
        r = requests.get(url, headers=headers, timeout=15) # Increased timeout
        r.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        soup = BeautifulSoup(r.content, 'html.parser')
        
        # Use absolute URL for images
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        images = [{'src': urljoin(base_url, i.get('src')), 'alt': i.get('alt', '')} for i in soup.find_all('img') if i.get('src')]
        
        # Remove script and style tags before counting words
        for s in soup(["script", "style"]): s.extract()
        
        # Get meta description
        meta_desc_tag = soup.find('meta', attrs={'name': 'description'})
        meta_description = meta_desc_tag['content'] if meta_desc_tag else "No Meta Description"
        
        return jsonify({'success': True, 'analysis': {
            'title': soup.title.string if soup.title else "No Title",
            'meta_description': meta_description, # ADDED: Meta description
            'h1_tags': [h.text.strip() for h in soup.find_all('h1')],
            'word_count': len(soup.get_text().split()),
            'images': images, 'total_images': len(images)
        }})
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 406: return jsonify({'error': 'Blocked by WAF (Error 406)'}), 406
        return jsonify({'error': f"HTTP Error: {e.response.status_code}"}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to connect to URL: {e}"}), 400
    except Exception as e: 
        app.logger.error(f"Competitor Analysis Error: {e}")
        return jsonify({'error': 'An internal error occurred during analysis.'}), 500

# --- WordPress ---
@app.route('/api/publish-wordpress', methods=['POST'])
@login_required
def api_publish_wordpress():
    data = request.get_json()
    wp_url = data.get('url', '').rstrip('/')
    username = data.get('username')
    password = data.get('password')
    title = data.get('title')
    content = data.get('content')
    
    # Input Validation
    if not (wp_url and username and password and title and content):
        return jsonify({'error': 'Missing WordPress credentials or content data.'}), 400
        
    creds = f"{username}:{password}"
    token = base64.b64encode(creds.encode()).decode('utf-8')
    headers = {'Authorization': f'Basic {token}', 'Content-Type': 'application/json'}
    payload = {'title': title, 'content': content, 'status': 'draft'}
    
    try:
        api_endpoint = f"{wp_url}/wp-json/wp/v2/posts"
        r = requests.post(api_endpoint, headers=headers, json=payload, timeout=10)
        
        if r.status_code == 201: 
            return jsonify({'success': True, 'link': r.json().get('link')})
        
        # Handle non-201 responses from WordPress API
        error_details = r.json().get('message', r.text) if r.content else r.text
        return jsonify({'error': f"WP API Error ({r.status_code}): {error_details}"}), r.status_code
        
    except requests.exceptions.RequestException as e: 
        return jsonify({'error': f"Failed to connect to WordPress site: {e}"}), 503
    except Exception as e: 
        app.logger.error(f"WordPress Publish Error: {e}")
        return jsonify({'error': 'An unexpected error occurred during publishing.'}), 500

# --- Delete Content ---
@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id:
        db.session.delete(c)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Authorization Error: Not your content.'}), 403

# --- Export ---
@app.route('/api/export/<int:id>/<fmt>')
@login_required
def api_export(id, fmt):
    c = Content.query.get_or_404(id)
    if c.user_id != current_user.id: 
        flash("Authorization Error: Cannot export content you don't own.", "danger")
        return "Auth Error", 403
        
    # Input validation for format
    if fmt not in ['txt', 'html']:
        return "Invalid export format", 400

    data = c.content if fmt == 'txt' else c.html_content or c.content # Fallback to content if html_content is None
    mime = 'text/plain' if fmt == 'txt' else 'text/html'
    
    # Sanitize filename better
    filename = re.sub(r'[\\/*?:"<>|\s]+', "-", c.title) or "document" 
    
    # Encode data safely and use BytesIO
    encoded_data = data.encode('utf-8')
    
    return send_file(BytesIO(encoded_data), 
                     mimetype=mime, 
                     as_attachment=True, 
                     download_name=f"{filename}.{fmt}")

# --- Sitemap Gen ---
@app.route('/api/generate-sitemap', methods=['POST'])
@login_required
def api_generate_sitemap():
    if current_user.tier == 'free': return jsonify({'error': 'Pro Feature'}), 403
    try:
        url = request.get_json().get('url')
        if not validators.url(url): return jsonify({'error': 'Invalid URL'}), 400
        
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; MySEOTool/1.0; +http://myseotool.com)'}
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status() # Raise exception for bad status codes
        
        soup = BeautifulSoup(r.content, 'html.parser')
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        links = set([url.rstrip('/')])
        for a in soup.find_all('a', href=True):
            full_url = urljoin(base_url, a['href'])
            
            # Check for same domain and ignore fragments/queries
            if urlparse(full_url).netloc == urlparse(url).netloc:
                links.add(full_url.split('#')[0].split('?')[0])
                
        # Limit to 50 links as per original code
        xml_links = list(links)[:50] 
        
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for link in xml_links:
            # Ensure links are correctly encoded in XML
            link = link.replace('&', '&amp;') 
            xml += f'  <url>\n    <loc>{link}</loc>\n    <changefreq>weekly</changefreq>\n  </url>\n'
        xml += '</urlset>'
        
        return jsonify({'success': True, 'sitemap': xml})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to fetch URL: {e}"}), 400
    except Exception as e: 
        app.logger.error(f"Sitemap Generation Error: {e}")
        return jsonify({'error': 'An internal error occurred during sitemap generation.'}), 500

# --- Robots Gen ---
@app.route('/api/generate-robots', methods=['POST'])
@login_required
def api_generate_robots():
    d = request.get_json()
    c = f"User-agent: {d.get('userAgent', '*')}\n"
    if d.get('allow'): c += f"Allow: {d.get('allow')}\n"
    if d.get('disallow'): c += f"Disallow: {d.get('disallow')}\n"
    if d.get('sitemap'): 
        # Ensure sitemap URL is valid (optional, but safe)
        if validators.url(d.get('sitemap')):
            c += f"\nSitemap: {d.get('sitemap')}"
            
    return jsonify({'success': True, 'content': c})

# ==========================================
# 9. ERROR HANDLERS (New Feature)
# ==========================================
@app.errorhandler(404)
def not_found_error(error):
    # Log the error (optional)
    # app.logger.warning(f"404 Not Found: {request.url}")
    return render_template('404.html'), 404 # Requires a '404.html' template

@app.errorhandler(403)
def forbidden_error(error):
    # Log the error (optional)
    # app.logger.warning(f"403 Forbidden: {request.url} by user {current_user.id if current_user.is_authenticated else 'Anon'}")
    flash("You do not have permission to access this resource.", "danger")
    return redirect(url_for('dashboard')), 403

# ==========================================
# 10. INITIALIZATION
# ==========================================
with app.app_context():
    try: 
        db.create_all()
    except Exception as e:
        # Better error handling for database connection failure
        print(f"Database Initialization Failed: {e}")

if __name__ == '__main__':
    # Using 0.0.0.0 is best for containerized environments (like Heroku/Docker)
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
