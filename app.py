from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
import re, os, requests, base64, json, validators, csv, random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from openai import OpenAI
import markdown
from io import BytesIO, StringIO
from sqlalchemy import text
from youtube_transcript_api import YouTubeTranscriptApi
from collections import Counter
from fpdf import FPDF
from threading import Thread  # <--- ADDED THIS IMPORT

# ==========================================
# 1. CONFIGURATION
# ==========================================
load_dotenv()
app = Flask(__name__)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///myseotoolver5.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

# --- UPDATED EMAIL CONFIGURATION (Hostinger SSL - Async Ready) ---
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 465           # Changed to 465 (Implicit SSL)
app.config['MAIL_USE_TLS'] = False      # Must be False for 465
app.config['MAIL_USE_SSL'] = True       # Must be True for 465
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'support@myseokingtool.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('My SEO King Tool Team', app.config['MAIL_USERNAME'])
app.config['MAIL_DEBUG'] = False

# --- PAYPAL CONFIGURATION ---
PAYPAL_EMAIL = os.environ.get('PAYPAL_EMAIL', 'your-paypal@email.com')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# --- GLOBAL TOOL LIST ---
TOOL_LIST = [
    'competitor-analyzer', 'keyword-research', 'sitemap-generator', 
    'robots-generator', 'image-seo', 'social-posts', 'alt-text-generator', 
    'content-outline', 'content-brief', 'lsi-keywords', 'email-subject', 
    'headline-analyzer', 'internal-linking', 'schema-generator', 'readability-checker',
    'faq-schema', 'youtube-script', 'meta-tags', 'plagiarism-checker', 'serp-analysis',
    'youtube-to-blog', 'image-generator', 'site-auditor', 'content-humanizer', 
    'article-wizard', 'bulk-writer', 'gbp-tool', 'geo-optimizer', 'backlink-outreach',
    'social-preview', 'keyword-density'
]

# --- PIPED MIRRORS ---
PIPED_INSTANCES = [
    "https://pipedapi.kavin.rocks",
    "https://api.piped.privacy.com.de",
    "https://pipedapi.moomoo.me",
    "https://pipedapi.smnz.de",
    "https://pipedapi.adminforge.de"
]

# ==========================================
# 1.5 ASYNC EMAIL HELPER (FIXES 502 ERRORS)
# ==========================================
def send_async_email(app_obj, msg):
    """Background task to send email without freezing the browser"""
    with app_obj.app_context():
        try:
            mail.send(msg)
            print(f"✅ Email sent to {msg.recipients}")
        except Exception as e:
            print(f"❌ Background email failed: {e}")

def send_email_background(subject, recipient, body):
    """Call this function to send emails safely"""
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    
    # Pass the actual app object to the thread
    app_obj = current_app._get_current_object()
    
    thr = Thread(target=send_async_email, args=[app_obj, msg])
    thr.start()

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

# --- PAYMENT MODEL (NEW) ---
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payment_id = db.Column(db.String(100), unique=True, nullable=True)
    payer_email = db.Column(db.String(120))
    amount = db.Column(db.Float, default=0)
    plan = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')  # pending, completed, rejected
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref=db.backref('payments', lazy=True))

@login_manager.user_loader
def load_user(user_id): 
    return User.query.get(int(user_id))

# ==========================================
# 3. FAVICON ROUTES (FOR SEO)
# ==========================================
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.ico'))

@app.route('/apple-touch-icon.png')
def apple_touch_icon():
    return redirect(url_for('static', filename='apple-touch-icon.png'))

@app.route('/favicon-32x32.png')
def favicon_32():
    return redirect(url_for('static', filename='favicon-32x32.png'))

@app.route('/favicon-16x16.png')
def favicon_16():
    return redirect(url_for('static', filename='favicon-16x16.png'))

@app.route('/site.webmanifest')
def webmanifest():
    manifest = {
        "name": "My SEO King Tool",
        "short_name": "MySEOKingTool",
        "icons": [
            {"src": "/static/android-chrome-192x192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/android-chrome-512x512.png", "sizes": "512x512", "type": "image/png"}
        ],
        "theme_color": "#4f46e5",
        "background_color": "#ffffff",
        "display": "standalone"
    }
    return jsonify(manifest)

# ==========================================
# 4. PAGE ROUTES
# ==========================================
@app.route('/')
def landing(): 
    if current_user.is_authenticated: 
        return redirect(url_for('dashboard'))
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
    if scores: 
        avg_score = sum(scores) / len(scores)

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

# --- DEDICATED TOOL PAGE ROUTES ---
@app.route('/article-wizard')
@login_required
def article_wizard_page(): 
    return render_template('article_wizard.html')

@app.route('/alt-text-generator')
@login_required
def alt_text_generator_page(): 
    return render_template('alt_text_generator.html')

@app.route('/bulk-writer')
@login_required
def bulk_writer_page():
    if current_user.tier == 'free':
        flash("Bulk Writing is a Pro Feature!", "warning")
        return redirect('/pricing')
    return render_template('bulk_writer.html')

@app.route('/sitemap-generator')
@login_required
def sitemap_generator_page():
    return render_template('sitemap_generator.html')

@app.route('/robots-generator')
@login_required
def robots_generator_page():
    return render_template('robots_generator.html')

# --- TECHNICAL SEO ROUTES ---
@app.route('/robots.txt')
def robots_txt():
    lines = [
        "User-agent: *", 
        "Disallow: /dashboard", 
        "Disallow: /editor", 
        "Disallow: /admin", 
        "Disallow: /profile", 
        f"Sitemap: {request.url_root}sitemap.xml"
    ]
    return "\n".join(lines), 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = request.url_root.rstrip('/')
    pages = ['/', '/pricing', '/login', '/signup']
    for slug in TOOL_LIST:
        pages.append(f'/tool/{slug}')

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += f'  <url>\n    <loc>{base_url}{page}</loc>\n    <changefreq>weekly</changefreq>\n  </url>\n'
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}

# ==========================================
# 5. AUTH ROUTES
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=data.get('email').lower()).first()
        if user and user.check_password(data.get('password')):
            if not user.is_active: 
                return jsonify({'error': 'Banned'}), 403
            login_user(user)
            return jsonify({'success': True, 'redirect': '/dashboard'})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: 
        return redirect('/dashboard')
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            if User.query.filter_by(email=data.get('email').lower()).first(): 
                return jsonify({'error': 'Email exists'}), 400
            
            hashed = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
            user = User(username=data.get('username'), email=data.get('email').lower(), password_hash=hashed)
            if User.query.count() == 0: 
                user.is_admin = True
            
            db.session.add(user)
            db.session.commit()
            login_user(user)

            # --- SENDING EMAIL IN BACKGROUND (Prevents 502 Timeout) ---
            try:
                body = f"Hi {user.username},\n\nWelcome to My SEO King Tool.\n\nCheers,\nTeam"
                send_email_background("Welcome to MySEO King! 👑", user.email, body)
            except: 
                pass
            # -----------------------------------------------------------

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
# 6. ADMIN & PAYMENT
# ==========================================
@app.route('/admin')
@login_required
def admin():
    if not getattr(current_user, 'is_admin', False): 
        return redirect('/dashboard')
    users = User.query.order_by(User.id.desc()).all()
    # Get pending payments for admin review
    pending_payments = Payment.query.filter_by(status='pending').order_by(Payment.created_at.desc()).all()
    return render_template('admin.html', users=users, total_content=Content.query.count(), pending_payments=pending_payments)

@app.route('/admin/export-users')
@login_required
def admin_export_users():
    if not getattr(current_user, 'is_admin', False): 
        return "Unauthorized", 403
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Email', 'Tier'])
    for u in User.query.all(): 
        cw.writerow([u.id, u.username, u.email, u.tier])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=users.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(user_id):
    if not getattr(current_user, 'is_admin', False): 
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        user.is_active = not user.is_active
        db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not getattr(current_user, 'is_admin', False): 
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id != current_user.id:
        db.session.delete(user)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>/upgrade', methods=['POST'])
@login_required
def admin_upgrade_user(user_id):
    if not getattr(current_user, 'is_admin', False): 
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    user.tier = data.get('tier')
    db.session.commit()
    return jsonify({'success': True})

@app.route('/payment/success/<plan_name>')
@login_required
def payment_success(plan_name):
    if plan_name == 'pro': 
        current_user.tier = 'pro king'
    elif plan_name == 'enterprise': 
        current_user.tier = 'enterprise'
    db.session.commit()
    return redirect('/dashboard')

# ==========================================
# PAYMENT VERIFICATION API
# ==========================================

@app.route('/api/verify-payment', methods=['POST'])
@login_required
def api_verify_payment():
    """API endpoint for submitting PayPal transaction ID"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id', '').strip().upper()
        email = data.get('email', '').strip().lower()
        
        if not transaction_id:
            return jsonify({'success': False, 'error': 'Transaction ID is required'}), 400
        
        if len(transaction_id) < 10:
            return jsonify({'success': False, 'error': 'Invalid Transaction ID format'}), 400
        
        # Check if this transaction already exists and is completed
        existing = Payment.query.filter_by(payment_id=transaction_id).first()
        if existing:
            if existing.status == 'completed':
                return jsonify({
                    'success': False, 
                    'already_exists': True,
                    'message': 'This transaction has already been verified and processed.'
                }), 400
            elif existing.status == 'pending':
                return jsonify({
                    'success': False,
                    'already_exists': True,
                    'message': 'This transaction is already pending verification.'
                }), 400
        
        # Find or create pending payment for this user
        pending_payment = Payment.query.filter_by(
            user_id=current_user.id,
            status='pending',
            payment_id=None
        ).order_by(Payment.created_at.desc()).first()
        
        if pending_payment:
            # Update existing pending payment
            pending_payment.payment_id = transaction_id
            pending_payment.payer_email = email
            pending_payment.notes = f'Manual submission - awaiting verification. Submitted: {datetime.utcnow()}'
        else:
            # Create new payment record for verification
            pending_payment = Payment(
                user_id=current_user.id,
                payment_id=transaction_id,
                payer_email=email,
                amount=0,  # Will be verified by admin
                plan='pending_verification',
                status='pending',
                notes=f'Manual submission - awaiting verification. Submitted: {datetime.utcnow()}'
            )
            db.session.add(pending_payment)
        
        db.session.commit()
        
        # Notify admin via email
        admin_body = f"""🔔 New Payment Verification Request

User Details:
- Username: {current_user.username}
- Email: {current_user.email}
- User ID: {current_user.id}

Payment Details:
- Transaction ID: {transaction_id}
- Payer Email: {email}
- Submitted At: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Please verify this transaction in PayPal and approve/reject in admin panel:
{url_for('admin', _external=True)}
"""
        send_email_background("🔔 Payment Verification Request", PAYPAL_EMAIL, admin_body)
        
        return jsonify({
            'success': True,
            'message': 'Transaction submitted successfully! We will verify and upgrade your account within 24 hours.'
        })
        
    except Exception as e:
        print(f"Payment verification error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred. Please try again.'}), 500

# --- ADMIN: APPROVE PAYMENT ---
@app.route('/admin/payment/<int:payment_id>/approve', methods=['POST'])
@login_required
def admin_approve_payment(payment_id):
    """Admin endpoint to approve a pending payment"""
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        payment = Payment.query.get_or_404(payment_id)
        
        if payment.status != 'pending':
            return jsonify({'error': 'Payment is not pending'}), 400
        
        # Update payment status
        payment.status = 'completed'
        payment.verified_at = datetime.utcnow()
        payment.amount = data.get('amount', 0)
        payment.plan = data.get('plan', 'pro king')
        payment.notes = f"{payment.notes}\nApproved by admin on {datetime.utcnow()}"
        
        # Upgrade user
        user = User.query.get(payment.user_id)
        if user:
            user.tier = data.get('plan', 'pro king')
            
            # Notify user via email
            user_body = f"""🎉 Payment Verified - Account Upgraded!

Hi {user.username},

Great news! Your payment has been verified and your account has been upgraded to {user.tier.upper()}.

Transaction ID: {payment.payment_id}
Plan: {user.tier.upper()}

You now have access to all premium features. Enjoy!

Best regards,
My SEO King Tool Team
"""
            send_email_background("🎉 Payment Verified - Account Upgraded!", user.email, user_body)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Payment approved and user upgraded!'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- ADMIN: REJECT PAYMENT ---
@app.route('/admin/payment/<int:payment_id>/reject', methods=['POST'])
@login_required
def admin_reject_payment(payment_id):
    """Admin endpoint to reject a pending payment"""
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        payment = Payment.query.get_or_404(payment_id)
        
        if payment.status != 'pending':
            return jsonify({'error': 'Payment is not pending'}), 400
        
        reason = data.get('reason', 'Transaction could not be verified')
        
        # Update payment status
        payment.status = 'rejected'
        payment.notes = f"{payment.notes}\nRejected by admin on {datetime.utcnow()}. Reason: {reason}"
        
        # Notify user via email
        user = User.query.get(payment.user_id)
        if user:
            user_body = f"""⚠️ Payment Verification Issue

Hi {user.username},

We were unable to verify your payment submission.

Transaction ID: {payment.payment_id}
Reason: {reason}

If you believe this is an error, please contact support with your PayPal receipt.

Best regards,
My SEO King Tool Team
"""
            send_email_background("⚠️ Payment Verification Issue", user.email, user_body)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Payment rejected and user notified.'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- GET PENDING PAYMENTS (for admin dashboard) ---
@app.route('/api/admin/pending-payments', methods=['GET'])
@login_required
def api_get_pending_payments():
    """Get all pending payments for admin review"""
    if not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        payments = Payment.query.filter_by(status='pending').order_by(Payment.created_at.desc()).all()
        
        result = []
        for p in payments:
            user = User.query.get(p.user_id)
            result.append({
                'id': p.id,
                'transaction_id': p.payment_id,
                'payer_email': p.payer_email,
                'user_id': p.user_id,
                'username': user.username if user else 'Unknown',
                'user_email': user.email if user else 'Unknown',
                'submitted_at': p.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'notes': p.notes
            })
        
        return jsonify({'success': True, 'payments': result})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==========================================
# 7. TOOL ROUTER
# ==========================================
@app.route('/tool/<tool_name>')
@login_required
def tool_view(tool_name):
    if tool_name == 'image-generator' and current_user.tier == 'free':
        flash("Pro Feature!", "warning")
        return redirect('/pricing')
    
    # Handle Manual Redirects
    if tool_name == 'article-wizard': 
        return redirect('/article-wizard')
    if tool_name == 'alt-text-generator': 
        return redirect('/alt-text-generator')
    if tool_name == 'bulk-writer': 
        return redirect('/bulk-writer')
    if tool_name == 'sitemap-generator': 
        return redirect('/sitemap-generator')
    if tool_name == 'robots-generator': 
        return redirect('/robots-generator')
    
    try:
        return render_template(f'{tool_name.replace("-", "_")}.html')
    except:
        return "Tool not found", 404

for t in TOOL_LIST:
    if t not in ['article-wizard', 'alt-text-generator', 'bulk-writer', 'sitemap-generator', 'robots-generator']:
        app.add_url_rule(f'/{t}', endpoint=t, view_func=lambda t=t: tool_view(t))
    if '-' in t: 
        app.add_url_rule(f'/{t}', endpoint=t.replace('-', '_'), view_func=lambda t=t: tool_view(t))

# ==========================================
# 8. API ENDPOINTS
# ==========================================

# --- BULK WRITER API (Single Article - Prevents Timeout) ---
@app.route('/api/bulk-write-single', methods=['POST'])
@login_required
def api_bulk_write_single():
    """Generate a single article - called multiple times from frontend"""
    if current_user.tier == 'free':
        return jsonify({'error': 'Upgrade to Pro for Bulk Writing!'}), 403
    
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Monthly limit reached'}), 403
    
    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        tone = data.get('tone', 'Professional')
        word_count = data.get('word_count', 800)
        
        if not keyword:
            return jsonify({'error': 'No keyword provided'}), 400
        
        prompt = f"""
Write a comprehensive, SEO-optimized blog post about: "{keyword}"

Requirements:
- Tone: {tone}
- Target word count: approximately {word_count} words
- Start with an engaging introduction that hooks the reader
- Use H2 (##) and H3 (###) headings to structure the content
- Include actionable tips and practical advice
- Add relevant examples where appropriate
- End with a strong conclusion summarizing key points
- Make it informative, engaging, and valuable for readers

Format the article using Markdown.
"""
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert SEO content writer who creates engaging, well-structured blog posts."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=2000,
            temperature=0.7
        )
        
        content = res.choices[0].message.content
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'keyword': keyword,
            'content': content,
            'html': markdown.markdown(content),
            'word_count': len(content.split())
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'keyword': data.get('keyword', 'Unknown')}), 500

# --- SITEMAP GENERATOR API ---
@app.route('/api/generate-sitemap', methods=['POST'])
@login_required
def api_generate_sitemap():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        
        if not base_url:
            return jsonify({'error': 'Please enter a URL'}), 400
        
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        
        parsed = urlparse(base_url)
        if not parsed.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        urls = data.get('urls', [])
        changefreq = data.get('changefreq', 'weekly')
        priority = data.get('priority', '0.8')
        include_lastmod = data.get('include_lastmod', True)
        
        if not urls:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                r = requests.get(base_url, headers=headers, timeout=10)
                soup = BeautifulSoup(r.content, 'html.parser')
                
                found_urls = set()
                found_urls.add(base_url)
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    
                    if href.startswith('/'):
                        full_url = base_url + href
                    elif href.startswith(base_url):
                        full_url = href
                    elif not href.startswith('http'):
                        full_url = urljoin(base_url, href)
                    else:
                        continue
                    
                    if parsed.netloc in full_url:
                        clean_url = full_url.split('#')[0].split('?')[0]
                        if clean_url and len(clean_url) < 500:
                            found_urls.add(clean_url)
                
                urls = list(found_urls)[:50]
                
            except Exception as e:
                urls = [base_url]
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        ]
        
        for url in urls:
            if url.strip():
                xml_lines.append('  <url>')
                xml_lines.append(f'    <loc>{url.strip()}</loc>')
                if include_lastmod:
                    xml_lines.append(f'    <lastmod>{today}</lastmod>')
                xml_lines.append(f'    <changefreq>{changefreq}</changefreq>')
                xml_lines.append(f'    <priority>{priority}</priority>')
                xml_lines.append('  </url>')
        
        xml_lines.append('</urlset>')
        
        sitemap_xml = '\n'.join(xml_lines)
        
        return jsonify({
            'success': True,
            'sitemap': sitemap_xml,
            'url_count': len(urls),
            'urls_found': urls
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- ROBOTS.TXT GENERATOR API ---
@app.route('/api/generate-robots', methods=['POST'])
@login_required
def api_generate_robots():
    try:
        data = request.get_json()
        
        base_url = data.get('url', '').rstrip('/')
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        
        user_agents = data.get('user_agents', ['*'])
        disallow_paths = data.get('disallow', [])
        allow_paths = data.get('allow', [])
        sitemap_url = data.get('sitemap', f'{base_url}/sitemap.xml')
        crawl_delay = data.get('crawl_delay', None)
        
        preset = data.get('preset', 'balanced')
        
        if preset == 'allow_all':
            disallow_paths = []
        elif preset == 'block_all':
            disallow_paths = ['/']
        elif preset == 'balanced':
            if not disallow_paths:
                disallow_paths = ['/admin', '/dashboard', '/api/', '/private/', '/tmp/', '/*.json$']
        elif preset == 'ecommerce':
            if not disallow_paths:
                disallow_paths = ['/cart', '/checkout', '/account', '/admin', '/api/', '/search?', '/*?sort=', '/*?filter=']
        elif preset == 'wordpress':
            if not disallow_paths:
                disallow_paths = ['/wp-admin/', '/wp-includes/', '/wp-content/plugins/', '/trackback/', '/feed/', '/?s=', '/search/']
        
        lines = []
        
        for agent in user_agents:
            lines.append(f'User-agent: {agent}')
            
            for path in disallow_paths:
                if path.strip():
                    lines.append(f'Disallow: {path.strip()}')
            
            for path in allow_paths:
                if path.strip():
                    lines.append(f'Allow: {path.strip()}')
            
            if crawl_delay:
                lines.append(f'Crawl-delay: {crawl_delay}')
            
            lines.append('')
        
        if sitemap_url:
            lines.append(f'Sitemap: {sitemap_url}')
        
        parsed = urlparse(base_url)
        lines.append(f'Host: {parsed.netloc}')
        
        robots_content = '\n'.join(lines)
        
        return jsonify({
            'success': True,
            'robots': robots_content
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- DOWNLOAD SITEMAP FILE ---
@app.route('/api/download-sitemap', methods=['POST'])
@login_required
def api_download_sitemap():
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        response = make_response(content)
        response.headers['Content-Type'] = 'application/xml'
        response.headers['Content-Disposition'] = 'attachment; filename=sitemap.xml'
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- DOWNLOAD ROBOTS FILE ---
@app.route('/api/download-robots', methods=['POST'])
@login_required
def api_download_robots():
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        response = make_response(content)
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = 'attachment; filename=robots.txt'
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- BACKLINK BUILDER (SAFE OUTREACH) ---
@app.route('/api/backlink-outreach', methods=['POST'])
@login_required
def api_backlink_outreach():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached'}), 403
    
    d = request.get_json()
    target_url = d.get('url')
    topic = d.get('topic')
    
    prompt = f"""
    Write a high-conversion 'Guest Post' or 'Link Insertion' email pitch.
    Target Website: {target_url}
    My Topic: {topic}
    
    Tone: Professional but personal.
    Subject Line: Catchy.
    Body: Compliment their recent work, explain why my content adds value to them, and propose the link.
    """
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Outreach Expert"},{"role":"user","content":prompt}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

# --- PUBLIC AUDIT ---
@app.route('/api/public-audit', methods=['POST'])
def api_public_audit():
    try:
        url = request.get_json().get('url')
        if not url: 
            return jsonify({'error': 'Enter URL'}), 400
        if not url.startswith('http'): 
            url = 'https://' + url
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=15)
        s = BeautifulSoup(r.content, 'html.parser')
        score = 100
        real_issues = []
        if not s.title: 
            score -= 20
            real_issues.append("Missing Title Tag")
        elif len(s.title.string) > 60: 
            score -= 5
            real_issues.append("Title Too Long")
        if not s.find('meta', attrs={'name':'description'}): 
            score -= 20
            real_issues.append("Missing Meta Description")
        if not s.find('h1'): 
            score -= 20
            real_issues.append("Missing H1 Heading")
        if score == 100: 
            real_issues.append("No critical errors found")
        return jsonify({'success': True, 'score': max(35,score), 'issues': real_issues})
    except: 
        return jsonify({'success': True, 'score': 42, 'issues': ['Server Response Timeout', 'Mobile Optimization Issues']})

# --- PRO AUDIT ---
@app.route('/api/audit-site', methods=['POST'])
@login_required
def api_audit_site():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'): 
            url = 'https://' + url
        start = datetime.now()
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}, timeout=30)
        load = round((datetime.now()-start).total_seconds(), 2)
        s = BeautifulSoup(r.content, 'html.parser')
        score = 100
        issues = []
        passed = []
        if not s.title: 
            score -= 20
            issues.append({"type":"critical","msg":"Missing Title","fix":"Add <title>"})
        else: 
            passed.append("Title Exists")
        if not s.find('meta', attrs={'name':'description'}): 
            score -= 20
            issues.append({"type":"critical","msg":"Missing Meta Desc","fix":"Add description"})
        else: 
            passed.append("Meta Description Found")
        if not s.find('h1'): 
            score -= 20
            issues.append({"type":"critical","msg":"Missing H1","fix":"Add H1 tag"})
        else: 
            passed.append("H1 Tag Found")
        imgs = s.find_all('img')
        miss = sum(1 for i in imgs if not i.get('alt'))
        if miss > 0: 
            score -= 5
            issues.append({"type":"warning","msg":f"{miss} Images missing Alt","fix":"Add alt text"})
        else: 
            passed.append("Images Optimized")
        return jsonify({
            'success': True, 
            'score': max(0,score), 
            'meta': {
                'url': url, 
                'title': s.title.string if s.title else "None", 
                'description': "...", 
                'load_time': f"{load}s", 
                'word_count': len(s.get_text().split()), 
                'link_count': len(s.find_all('a')), 
                'canonical': ""
            },
            'issues': issues, 
            'passed': passed
        })
    except Exception as e: 
        return jsonify({'error': f"Failed: {str(e)}"}), 500

@app.route('/api/generate-image', methods=['POST'])
@login_required
def api_generate_image():
    if current_user.tier == 'free': 
        return jsonify({'error': 'Upgrade to Pro!'}), 403
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.images.generate(model="dall-e-3", prompt=request.get_json().get('prompt'), size="1024x1024", quality="standard", n=1)
        current_user.ai_requests_this_month += 5
        db.session.commit()
        return jsonify({'success': True, 'image_url': res.data[0].url})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/humanize-text', methods=['POST'])
@login_required
def api_humanize_text():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached'}), 403
    try:
        res = client.chat.completions.create(model="gpt-4o", messages=[{"role":"system","content":"Rewriter"},{"role":"user","content":f"Humanize: {request.get_json().get('content')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/article-wizard', methods=['POST'])
@login_required
def api_article_wizard():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached'}), 403
    try:
        d = request.get_json()
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Writer"},{"role":"user","content":f"Blog about: {d.get('topic')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached.'}), 403
    data = request.get_json()
    video_url = data.get('url')
    try:
        vid = video_url.split("v=")[1].split("&")[0] if "v=" in video_url else video_url.split("youtu.be/")[1].split("?")[0]
        full_text = ""
        mirrors = PIPED_INSTANCES.copy()
        random.shuffle(mirrors)
        for m in mirrors:
            try:
                r = requests.get(f"{m}/streams/{vid}", timeout=5)
                if r.status_code == 200:
                    subs = r.json().get('subtitles', [])
                    tgt = next((s for s in subs if 'en' in s.get('code','')), subs[0] if subs else None)
                    if tgt:
                        lines = requests.get(tgt['url']).text.splitlines()
                        clean = [l.strip() for l in lines if '-->' not in l and 'WEBVTT' not in l and l.strip()]
                        full_text = " ".join(clean)
                        if len(full_text) > 50: 
                            break
            except: 
                continue
        if not full_text: 
            return jsonify({'error': "No captions found."}), 400
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Writer"},{"role":"user","content":f"Blog from transcript: {full_text[:15000]}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":request.get_json().get('keyword')}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html_content': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/save-content', methods=['POST'])
@login_required
def api_save_content():
    d = request.get_json()
    if d.get('id'):
        c = Content.query.get(d.get('id'))
        if c and c.user_id == current_user.id:
            c.title = d.get('title')
            c.content = d.get('content')
            c.html_content = d.get('html_content')
            c.keyword = d.get('keyword')
            c.word_count = len(d.get('content','').split())
            db.session.commit()
            return jsonify({'success': True, 'id': c.id})
    new_c = Content(
        user_id=current_user.id, 
        title=d.get('title'), 
        content=d.get('content'), 
        html_content=d.get('html_content'), 
        keyword=d.get('keyword'), 
        word_count=len(d.get('content','').split())
    )
    db.session.add(new_c)
    current_user.content_count += 1
    db.session.commit()
    return jsonify({'success': True, 'id': new_c.id})

@app.route('/api/publish-wordpress', methods=['POST'])
@login_required
def api_publish_wordpress():
    d = request.get_json()
    wp = d.get('url').rstrip('/')
    creds = f"{d.get('username')}:{d.get('password')}"
    t = base64.b64encode(creds.encode()).decode('utf-8')
    try:
        r = requests.post(f"{wp}/wp-json/wp/v2/posts", headers={'Authorization': f'Basic {t}', 'Content-Type': 'application/json'}, json={'title':d.get('title'),'content':d.get('content'),'status':'draft'})
        return jsonify({'success': True, 'link': r.json().get('link')})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-content/<int:id>', methods=['POST'])
@login_required
def api_delete(id):
    c = Content.query.get_or_404(id)
    if c.user_id == current_user.id: 
        db.session.delete(c)
        db.session.commit()
    return jsonify({'success': True})

# --- HELPER APIs ---
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

# --- REAL READABILITY LOGIC ---
@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_readability():
    try:
        text_content = request.get_json().get('content', '')
        if not text_content: 
            return jsonify({'error': 'No text provided'}), 400

        words = [w for w in text_content.split() if len(w) > 0]
        sentences = [s for s in text_content.replace('!', '.').replace('?', '.').split('.') if len(s) > 0]
        
        total_words = len(words)
        total_sentences = len(sentences) if len(sentences) > 0 else 1
        avg_sentence_len = total_words / total_sentences

        def count_syllables(word):
            word = word.lower()
            count = 0
            vowels = "aeiouy"
            if len(word) == 0: 
                return 1
            if word[0] in vowels: 
                count += 1
            for index in range(1, len(word)):
                if word[index] in vowels and word[index - 1] not in vowels:
                    count += 1
            if word.endswith("e"): 
                count -= 1
            if count == 0: 
                count += 1
            return count

        total_syllables = sum(count_syllables(w) for w in words)
        
        if total_words == 0: 
            return jsonify({'error': 'No words found'}), 400
        
        score = 206.835 - (1.015 * avg_sentence_len) - (84.6 * (total_syllables / total_words))
        score = round(score, 1)

        difficulty = "Very Easy"
        grade = "5th Grade"
        color = "success"
        
        if score < 30: 
            difficulty = "Very Confusing"
            grade = "College Grad"
            color = "danger"
        elif score < 50: 
            difficulty = "Difficult"
            grade = "College"
            color = "warning"
        elif score < 60: 
            difficulty = "Fairly Difficult"
            grade = "10th-12th Grade"
            color = "warning"
        elif score < 70: 
            difficulty = "Standard"
            grade = "8th-9th Grade"
            color = "primary"
        elif score < 80: 
            difficulty = "Fairly Easy"
            grade = "7th Grade"
            color = "success"
        elif score < 90: 
            difficulty = "Easy"
            grade = "6th Grade"
            color = "success"

        reading_time = f"{max(1, round(total_words / 200))} min"

        return jsonify({
            'success': True,
            'stats': {
                'score': score,
                'grade': grade,
                'difficulty': difficulty,
                'words': total_words,
                'sentences': total_sentences,
                'reading_time': reading_time,
                'color': color
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/improve-readability', methods=['POST'])
@login_required
def api_improve_readability():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'AI Limit reached for this month. Please upgrade.'}), 403

    try:
        text_content = request.get_json().get('content', '')
        if not text_content: 
            return jsonify({'error': 'No text provided'}), 400

        prompt = f"""
        Rewrite the following text to improve its Flesch-Kincaid readability score.
        Target: 7th-8th Grade Level (Score 60-70).
        
        Rules:
        - Use shorter sentences.
        - Use simpler vocabulary.
        - Break up long paragraphs.
        - Keep the original meaning.
        
        Text:
        {text_content[:3000]}
        """
        
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"You are a professional editor."},{"role":"user","content":prompt}]
        )
        
        current_user.ai_requests_this_month += 1
        db.session.commit()

        return jsonify({'success': True, 'content': res.choices[0].message.content})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- UPDATED SCHEMA GENERATOR (3-in-1) ---
@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_schema():
    try:
        data = request.get_json()
        schema_type = data.get('type')
        result = {}

        if schema_type == 'faq':
            result = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": []
            }
            for qa in data.get('questions', []):
                if qa.get('q') and qa.get('a'):
                    result["mainEntity"].append({
                        "@type": "Question",
                        "name": qa['q'],
                        "acceptedAnswer": {
                            "@type": "Answer",
                            "text": qa['a']
                        }
                    })

        elif schema_type == 'article':
            result = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": data.get('headline', ''),
                "image": [data.get('image', '')],
                "datePublished": data.get('date', ''),
                "author": {
                    "@type": "Person",
                    "name": data.get('author', '')
                }
            }

        elif schema_type == 'local':
            result = {
                "@context": "https://schema.org",
                "@type": "LocalBusiness",
                "name": data.get('name', ''),
                "image": data.get('image', ''),
                "telephone": data.get('phone', ''),
                "address": {
                    "@type": "PostalAddress",
                    "streetAddress": data.get('address', ''),
                    "addressLocality": data.get('city', ''),
                    "addressRegion": data.get('region', ''),
                    "postalCode": data.get('zip', ''),
                    "addressCountry": data.get('country', '')
                },
                "priceRange": data.get('priceRange', '$$')
            }

        return jsonify({'success': True, 'json': json.dumps(result, indent=4)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-competitor', methods=['POST'])
@login_required
def api_competitor():
    try:
        r = requests.get(request.get_json().get('url'), headers={'User-Agent':'Mozilla/5.0'})
        s = BeautifulSoup(r.content, 'html.parser')
        return jsonify({
            'success': True, 
            'analysis': {
                'title': s.title.string if s.title else 'No Title', 
                'word_count': len(s.get_text().split()), 
                'h1_tags': [h.text for h in s.find_all('h1')], 
                'images': [], 
                'total_images': 0
            }
        })
    except: 
        return jsonify({'error': 'Failed to analyze URL'})

@app.route('/api/generate-clusters', methods=['POST'])
@login_required
def api_clusters():
    res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"JSON"},{"role":"user","content":f"Clusters for {request.get_json().get('keyword')} as JSON"}])
    return jsonify({'success':True, 'clusters': json.loads(res.choices[0].message.content.replace('```json','').replace('```','').strip())})

@app.route('/api/gbp-generate', methods=['POST'])
@login_required
def api_gbp_generate():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    d = request.get_json()
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"Local SEO"},{"role":"user","content":f"Write GBP {d.get('mode')} for {d.get('business')}"}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/api/geo-optimize', methods=['POST'])
@login_required
def api_geo_optimize():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']: 
        return jsonify({'error': 'Limit reached'}), 403
    keyword = request.get_json().get('keyword')
    try:
        res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"system","content":"SEO"},{"role":"user","content":f"Create GEO Direct Answer block for: '{keyword}'."}])
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content, 'html': markdown.markdown(res.choices[0].message.content)})
    except Exception as e: 
        return jsonify({'error': str(e)}), 500

@app.route('/test-email')
def test_email():
    try:
        # Use the new Async function
        send_email_background("Test Async", 'dilawarahsanrizvi7@gmail.com', "This email was sent in background.")
        return "Email process started (Async)"
    except Exception as e: 
        return f"Err: {e}"

@app.route('/fix-db')
def fix_db():
    try:
        with db.engine.connect() as conn: 
            conn.execute(text("ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'free';"))
            conn.commit()
        return "DB Fixed"
    except: 
        return "Err"

# ==========================================
# NEW FEATURES APIs
# ==========================================

# 1. SOCIAL MEDIA PREVIEW API
@app.route('/api/analyze-social', methods=['POST'])
@login_required
def api_analyze_social():
    try:
        data = request.get_json()
        target_url = data.get('url')
        if not target_url.startswith('http'): 
            target_url = 'https://' + target_url
        
        headers = {'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'}
        r = requests.get(target_url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        def get_meta(prop):
            t = soup.find('meta', property=prop) or soup.find('meta', attrs={'name': prop})
            return t['content'] if t else ""

        og_image = get_meta('og:image')
        if og_image and not og_image.startswith('http'):
            og_image = urljoin(target_url, og_image)

        result = {
            'og_title': get_meta('og:title') or (soup.title.string if soup.title else ''),
            'og_desc': get_meta('og:description') or get_meta('description'),
            'og_image': og_image,
            'og_url': get_meta('og:url') or target_url,
            'twitter_card': get_meta('twitter:card'),
            'twitter_title': get_meta('twitter:title'),
        }
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 2. KEYWORD DENSITY API
@app.route('/api/analyze-density', methods=['POST'])
@login_required
def api_analyze_density():
    try:
        import string
        
        data = request.get_json()
        text_content = ""
        
        if data.get('type') == 'url':
            url = data.get('content')
            if not url.startswith('http'): 
                url = 'https://' + url
            r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            soup = BeautifulSoup(r.content, 'html.parser')
            for script in soup(["script", "style"]): 
                script.extract()
            text_content = soup.get_text()
        else:
            text_content = data.get('content')

        words = text_content.lower().translate(str.maketrans('', '', string.punctuation)).split()
        stop_words = {"the","is","at","of","on","and","a","an","to","in","for","with","as","by","but","or","from","up","down","my","this","that","it","be","are","was","were","have","has","had","not","i","you","he","she","we","they"}
        filtered_words = [w for w in words if w not in stop_words and len(w) > 2]
        total_words = len(filtered_words)
        
        if total_words == 0: 
            return jsonify({'error': 'No content found'}), 400
        
        counter = Counter(filtered_words)
        most_common = counter.most_common(15)
        
        results = []
        for word, count in most_common:
            results.append({'word': word, 'count': count, 'density': round((count / total_words) * 100, 2)})
            
        return jsonify({'success': True, 'results': results, 'total_words': len(words)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 3. PDF REPORT GENERATOR API
@app.route('/api/generate-report', methods=['POST'])
@login_required
def api_generate_report():
    try:
        data = request.get_json()
        pdf = FPDF()
        pdf.add_page()
        
        pdf.set_font("Arial", "B", 20)
        pdf.set_text_color(79, 70, 229)
        pdf.cell(0, 10, "My SEO King Tool - Audit Report", 0, 1, "C")
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f"Target URL: {data.get('url')}", 0, 1)
        pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 1)
        pdf.cell(0, 10, f"SEO Score: {data.get('score')}/100", 0, 1)
        pdf.ln(10)
        
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(220, 53, 69)
        pdf.cell(0, 10, "Critical Issues Found:", 0, 1)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        
        if data.get('issues'):
            for issue in data.get('issues'):
                msg = issue.get('msg', issue) if isinstance(issue, dict) else issue
                pdf.cell(0, 10, f"- {msg}", 0, 1)
        else:
            pdf.cell(0, 10, "No critical issues found!", 0, 1)
        
        pdf.ln(10)
        
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(25, 135, 84)
        pdf.cell(0, 10, "Passed Checks:", 0, 1)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)
        
        if data.get('passed'):
            for item in data.get('passed'):
                pdf.cell(0, 10, f"- {item}", 0, 1)
                
        response = make_response(pdf.output(dest='S').encode('latin-1'))
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=seo_report.pdf'
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 4. YOUTUBE VIDEO SCRIPT API
@app.route('/api/generate-video-script', methods=['POST'])
@login_required
def api_generate_video_script():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    data = request.get_json()
    topic = data.get('topic')
    tone = data.get('tone', 'Engaging')
    
    prompt = f"""
    Create a structured YouTube Video Script.
    Topic: {topic}
    Tone: {tone}
    
    Structure:
    1. Hook (0-30s): Catchy opening.
    2. Intro: What will be covered.
    3. Body: 3 main points.
    4. CTA: Call to action.
    
    Format using Markdown headings.
    """
    
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"You are a YouTuber."},{"role":"user","content":prompt}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({
            'success': True, 
            'content': content,
            'html': markdown.markdown(content)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 5. SOCIAL MEDIA POST GENERATOR API
@app.route('/api/generate-social-posts', methods=['POST'])
@login_required
def api_generate_social_posts():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    data = request.get_json()
    topic = data.get('topic')
    
    prompt = f"""
    Write 3 distinct social media posts about: "{topic}".
    
    1. LinkedIn Post: Professional, use bullet points, end with a thought-provoking question.
    2. Twitter Thread (3 tweets): Short, punchy, informative.
    3. Instagram Caption: Casual, engaging, include 5 relevant hashtags.
    
    Format the output clearly with headers (e.g., ### LinkedIn).
    """
    
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"Social Media Expert."},{"role":"user","content":prompt}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({
            'success': True, 
            'content': content,
            'html': markdown.markdown(content)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 6. COMPETITOR SPY API
@app.route('/api/spy-competitor', methods=['POST'])
@login_required
def api_spy_competitor():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
        
    try:
        import string
        
        url = request.get_json().get('url')
        if not url.startswith('http'): 
            url = 'https://' + url
        
        r = requests.get(url, headers={'User-Agent':'Mozilla/5.0'}, timeout=15)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        title = soup.title.string if soup.title else "No Title"
        h1s = [h.get_text().strip() for h in soup.find_all('h1')]
        h2s = [h.get_text().strip() for h in soup.find_all('h2')[:5]]
        text_content = soup.get_text()
        word_count = len(text_content.split())
        
        words = text_content.lower().translate(str.maketrans('', '', string.punctuation)).split()
        stop_words = {"the","is","at","of","on","and","a","an","to","in","for","with","as","by","but","or","from","up","down","my","this","that","it","be","are","was","were","have","has","had","not","i","you","he","she","we","they"}
        filtered_words = [w for w in words if w not in stop_words and len(w) > 3]
        common_words = [w[0] for w in Counter(filtered_words).most_common(8)]
        
        prompt = f"""
        Analyze this competitor's content strategy:
        URL: {url}
        Title: {title}
        H1: {h1s}
        Top Keywords: {common_words}
        Word Count: {word_count}
        
        Provide 3 specific insights on why they might be ranking well, and 3 specific ways I can outrank them.
        Keep it actionable and punchy.
        """
        
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"SEO Strategist."},{"role":"user","content":prompt}]
        )
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': {
                'title': title,
                'word_count': word_count,
                'h1': h1s,
                'h2_sample': h2s,
                'keywords': common_words,
                'strategy': markdown.markdown(res.choices[0].message.content)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 7. AI KEYWORD RESEARCH & CLUSTER API
@app.route('/api/research-keywords', methods=['POST'])
@login_required
def api_research_keywords():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    data = request.get_json()
    seed = data.get('seed')
    
    prompt = f"""
    Act as a master SEO strategist.
    Seed Keyword: "{seed}"
    
    Generate a JSON list of 15 highly relevant Long-Tail Keywords.
    For each keyword, provide:
    1. "keyword": The keyword string.
    2. "intent": (Informational, Commercial, or Transactional).
    3. "difficulty": A score from 1-100 (Estimated).
    4. "content_idea": A catchy blog post title for this keyword.
    
    Return ONLY valid JSON array format. No markdown.
    """
    
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"JSON Generator"},{"role":"user","content":prompt}]
        )
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        raw = res.choices[0].message.content.replace('```json','').replace('```','').strip()
        
        return jsonify({
            'success': True, 
            'keywords': json.loads(raw)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 8. SMART CONTENT OUTLINE API
@app.route('/api/generate-outline', methods=['POST'])
@login_required
def api_generate_outline():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    data = request.get_json()
    topic = data.get('topic')
    
    prompt = f"""
    Create a comprehensive, SEO-optimized blog post outline for the topic: "{topic}".
    
    Structure:
    1. Catchy H1 Title.
    2. Introduction (Hook).
    3. 4-5 H2 Sections (Logical flow).
    4. Under each H2, list 3 bullet points of what to cover.
    5. Conclusion & Key Takeaways.
    
    Format using Markdown.
    """
    
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role":"system","content":"SEO Content Strategist."},{"role":"user","content":prompt}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({
            'success': True, 
            'content': content,
            'html': markdown.markdown(content)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==========================================
# RUN APPLICATION
# ==========================================
if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()
    app.run(debug=True, port=int(os.environ.get('PORT', 5001)))