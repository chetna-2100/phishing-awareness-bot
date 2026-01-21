import streamlit as st
import re
from urllib.parse import urlparse
import requests
import time
from datetime import datetime

# -------------------------------------
# PAGE CONFIG
# -------------------------------------
st.set_page_config(
    page_title="Phishing Detection AI",
    layout="wide"
)

# Initialize session state for navigation
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 0

# -------------------------------------
# API CONFIGURATION
# -------------------------------------
API_BASE_URL = "http://127.0.0.1:8000"  # Your FastAPI backend URL

# Initialize session state for dashboard stats
if 'urls_scanned' not in st.session_state:
    st.session_state.urls_scanned = 0
if 'threats_detected' not in st.session_state:
    st.session_state.threats_detected = 0
if 'emails_analyzed' not in st.session_state:
    st.session_state.emails_analyzed = 0
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# -------------------------------------
# API COMMUNICATION FUNCTIONS
# -------------------------------------

def check_api_health():
    """Check if API is running"""
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=2)
        return response.status_code == 200
    except:
        return False

def predict_url_api(url):
    """Send URL to API for prediction"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/predict/url",
            json={"url": url},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return None

def predict_email_api(email_text):
    """Send email to API for prediction"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/predict/email",
            json={"email_text": email_text},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return None

def predict_sms_api(sms_text):
    """Send SMS to API for prediction"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/predict/sms",
            json={"sms_text": sms_text},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return None

# -------------------------------------
# PHISHING DETECTION LOGIC (Fallback)
# -------------------------------------

def extract_url_features(url):
    """Extract features from URL for phishing detection"""
    features = {}
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Feature 1: URL Length (phishing URLs are often long)
        features['url_length'] = len(url)
        features['is_long'] = len(url) > 75
        
        # Feature 2: Number of dots in domain
        features['dot_count'] = domain.count('.')
        features['excessive_dots'] = domain.count('.') > 3
        
        # Feature 3: Presence of IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['has_ip'] = bool(re.search(ip_pattern, domain))
        
        # Feature 4: Presence of @ symbol (can hide real domain)
        features['has_at'] = '@' in url
        
        # Feature 5: Presence of double slash in path
        features['double_slash_path'] = '//' in path
        
        # Feature 6: Number of subdomains
        subdomains = domain.split('.')
        features['subdomain_count'] = len(subdomains) - 2 if len(subdomains) > 2 else 0
        features['excessive_subdomains'] = features['subdomain_count'] > 3
        
        # Feature 7: Presence of hyphen in domain (often used in phishing)
        features['has_hyphen'] = '-' in domain
        
        # Feature 8: HTTPS check
        features['is_https'] = parsed.scheme == 'https'
        
        # Feature 9: Suspicious keywords
        suspicious_words = ['login', 'verify', 'account', 'update', 'secure', 'banking', 
                           'signin', 'confirm', 'suspended', 'locked', 'unusual']
        features['suspicious_keywords'] = sum(1 for word in suspicious_words if word in url.lower())
        
        # Feature 10: Domain length
        features['domain_length'] = len(domain)
        features['long_domain'] = len(domain) > 30
        
        # Feature 11: Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.review']
        features['suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Feature 12: Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
        features['is_shortener'] = any(shortener in domain for shortener in shorteners)
        
        return features, parsed, domain
        
    except Exception as e:
        return None, None, None


def calculate_risk_score(features):
    """Calculate risk score based on extracted features"""
    score = 0
    reasons = []
    
    # Scoring logic
    if features['is_long']:
        score += 15
        reasons.append("⚠️ Unusually long URL")
    
    if features['has_ip']:
        score += 25
        reasons.append("🚨 Uses IP address instead of domain name")
    
    if features['has_at']:
        score += 20
        reasons.append("🚨 Contains '@' symbol (may hide real domain)")
    
    if features['excessive_dots']:
        score += 15
        reasons.append("⚠️ Too many dots in domain")
    
    if features['excessive_subdomains']:
        score += 15
        reasons.append("⚠️ Excessive subdomains detected")
    
    if not features['is_https']:
        score += 10
        reasons.append("⚠️ Not using HTTPS")
    
    if features['suspicious_keywords'] > 2:
        score += 20
        reasons.append(f"🚨 Multiple suspicious keywords found ({features['suspicious_keywords']})")
    elif features['suspicious_keywords'] > 0:
        score += 10
        reasons.append(f"⚠️ Suspicious keywords detected")
    
    if features['long_domain']:
        score += 10
        reasons.append("⚠️ Unusually long domain name")
    
    if features['suspicious_tld']:
        score += 20
        reasons.append("🚨 Suspicious top-level domain (TLD)")
    
    if features['is_shortener']:
        score += 15
        reasons.append("⚠️ URL shortener detected (hides real destination)")
    
    if features['has_hyphen']:
        score += 5
        reasons.append("⚠️ Contains hyphen in domain")
    
    return min(score, 100), reasons


def check_known_safe_domains(domain):
    """Check if domain is from known safe list"""
    safe_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
        'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com'
    ]
    
    # Check if domain or any parent domain is in safe list
    for safe in safe_domains:
        if domain == safe or domain.endswith('.' + safe):
            return True
    return False

def update_dashboard_stats(prediction_label):
    """Update dashboard statistics"""
    try:
        st.session_state.urls_scanned += 1
        if prediction_label == "phishing" or prediction_label == 1:
            st.session_state.threats_detected += 1
        
        # Add to scan history
        st.session_state.scan_history.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'result': prediction_label
        })
        
        # Keep only last 100 scans
        if len(st.session_state.scan_history) > 100:
            st.session_state.scan_history = st.session_state.scan_history[-100:]
    except Exception as e:
        pass

# -------------------------------------
# CUSTOM CSS FOR MODERN UI
# -------------------------------------
page_bg = '''
<style>
/* Background */
.stApp {
    background: radial-gradient(circle at top, #0a0f1f, #000000);
    color: white;
    font-family: 'Poppins', sans-serif;
}

/* Animated shield */
@keyframes glow {
    0% { text-shadow: 0 0 10px #36e2f5; }
    50% { text-shadow: 0 0 35px #00e1ff; }
    100% { text-shadow: 0 0 10px #36e2f5; }
}
.shield {
    font-size: 80px;
    text-align: center;
    animation: glow 2s infinite;
}

/* Title glow effect */
.title-glow {
    font-size: 58px;
    font-weight: 800;
    text-align: center;
    color: #36e2f5;
    text-shadow: 0px 0px 30px #1ee3ff;
}

/* Subtitle */
.subtitle {
    text-align: center;
    font-size: 22px;
    color: #b8d1f3;
}

/* Tag status box */
.status-box {
    background-color: #003b2e;
    padding: 8px 20px;
    border-radius: 30px;
    color: #3cffd0;
    font-weight: 600;
    width: max-content;
    margin: auto;
    border: 1px solid #28ffcd;
}

.status-box-offline {
    background-color: #3b0000;
    padding: 8px 20px;
    border-radius: 30px;
    color: #ff6b6b;
    font-weight: 600;
    width: max-content;
    margin: auto;
    border: 1px solid #ff4d4d;
}

/* Streamlit button styling */
.stButton > button {
    background-color: #081b33 !important;
    color: #ffffff !important;
    padding: 22px !important;
    border-radius: 14px !important;
    border: 1px solid #13345f !important;
    transition: 0.2s ease !important;
    font-size: 18px !important;
    font-weight: 600 !important;
    width: 100% !important;
}
.stButton > button:hover {
    background-color: #0f2e54 !important;
    border-color: #3ec7ff !important;
    transform: scale(1.05) !important;
    color: #ffffff !important;
}

/* Small scan buttons */
.stButton > button[kind="primary"] {
    padding: 10px 24px !important;
    font-size: 16px !important;
    width: auto !important;
    display: inline-block !important;
    color: #ffffff !important;
}

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
}

.stTabs [data-baseweb="tab"] {
    color: #ffffff !important;
    background-color: transparent !important;
    border-bottom: 2px solid transparent !important;
    padding: 10px 20px !important;
    font-size: 16px !important;
    font-weight: 500 !important;
}

.stTabs [aria-selected="true"] {
    color: #3ec7ff !important;
    border-bottom: 2px solid #3ec7ff !important;
    background-color: rgba(62, 199, 255, 0.1) !important;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #3ec7ff !important;
    background-color: rgba(62, 199, 255, 0.05) !important;
}

/* Input box */
input, textarea {
    background-color: #0d1a30 !important;
    color: white !important;
    border-radius: 8px !important;
}

/* Result boxes */
.result-box-safe {
    padding: 20px;
    border-radius: 10px;
    background-color: rgba(0, 255, 0, 0.1);
    border-left: 4px solid #00ff00;
    color: #a8ffbf;
    font-size: 18px;
}
.result-box-warning {
    padding: 20px;
    border-radius: 10px;
    background-color: rgba(255, 165, 0, 0.1);
    border-left: 4px solid #ffa500;
    color: #ffd699;
    font-size: 18px;
}
.result-box-danger {
    padding: 20px;
    border-radius: 10px;
    background-color: rgba(255, 0, 0, 0.1);
    border-left: 4px solid #ff4d4d;
    color: #ff9e9e;
    font-size: 18px;
}

/* Dashboard cards */
.card {
    background: #08162b;
    padding: 18px;
    border-radius: 16px;
    border: 1px solid #12345f;
    text-align: center;
    color: #bfe2ff;
    transition: 0.3s;
}
.card:hover {
    transform: scale(1.03);
    border-color: #3ec7ff;
}

/* Footer */
.footer {
    text-align: center;
    margin-top: 40px;
    color: #6eaad8;
    font-size: 14px;
}

/* Score badge */
.score-badge {
    display: inline-block;
    padding: 10px 20px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 20px;
    margin: 10px 0;
}
</style>
'''

st.markdown(page_bg, unsafe_allow_html=True)

# -------------------------------------
# CHECK API STATUS
# -------------------------------------
api_online = check_api_health()

# -------------------------------------
# HEADER
# -------------------------------------
st.markdown("<div class='shield'>🛡️</div>", unsafe_allow_html=True)

if api_online:
    st.markdown("<div class='status-box'>● SYSTEM ACTIVE - API CONNECTED</div>", unsafe_allow_html=True)
else:
    st.markdown("<div class='status-box-offline'>● API OFFLINE - FALLBACK MODE</div>", unsafe_allow_html=True)
    st.warning("⚠️ Backend API is not responding. Using local detection mode.")

st.markdown("<h1 class='title-glow'>Protect Your<br>Digital Identity</h1>", unsafe_allow_html=True)
st.markdown("<p class='subtitle'>Advanced AI-powered phishing detection that analyzes URLs, emails, and messages in real time.</p>",
            unsafe_allow_html=True)

st.write("")


# -------------------------------------
# FEATURE BUTTONS WITH NAVIGATION
# -------------------------------------
st.markdown("### 🎯 Quick Access")
def set_tab(tab_index):
    st.session_state.active_tab = tab_index

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.button("🛡️ URL Scanner", key="nav_url", on_click=set_tab, args=(0,))

with col2:
    st.button("📧 Email Analysis", key="nav_email", on_click=set_tab, args=(1,))

with col3:
    st.button("📱 SMS Detection", key="nav_sms", on_click=set_tab, args=(2,))

with col4:
    st.button("🔐 Privacy Guard", key="nav_privacy", on_click=set_tab, args=(3,))


# -------------------------------------
# LIVE DASHBOARD SUMMARY CARDS
# -------------------------------------
st.subheader("📊 Live Security Dashboard")

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown(f"<div class='card'><h2>🔍 {st.session_state.urls_scanned}</h2>URLs Scanned</div>", unsafe_allow_html=True)

with c2:
    st.markdown(f"<div class='card'><h2>⚠️ {st.session_state.threats_detected}</h2>Threats Detected</div>", unsafe_allow_html=True)

with c3:
    st.markdown(f"<div class='card'><h2>📩 {st.session_state.emails_analyzed}</h2>Emails Analyzed</div>", unsafe_allow_html=True)

st.write("---")

# -------------------------------------
# TABBED INTERFACE WITH NAVIGATION
# -------------------------------------
tab1, tab2, tab3 = st.tabs(["🔗 URL Scanner", "📧 Email Analysis", "📱 SMS Detection"])

# Set active tab based on button clicks
if st.session_state.active_tab == 0:
    tab1.write("")  # Activate URL Scanner tab
elif st.session_state.active_tab == 1:
    tab2.write("")  # Activate Email Analysis tab
elif st.session_state.active_tab == 2:
    tab3.write("")  # Activate SMS Detection tab

# -------------------------------------
# TAB 1: URL SCANNER
# -------------------------------------
if st.session_state.active_tab == 0:
    st.subheader("🔎 URL Scanner")
    
    user_url = st.text_input("🔗 Enter URL for Analysis:", key="url_input")
    
    if st.button("Scan URL", key="scan_url_btn", type="primary"):
        if user_url.strip() == "":
            st.warning("⚠️ Please enter a URL.")
        else:
            with st.spinner("🔍 Analyzing URL..."):
                # Extract features using local detection (always)
                features, parsed, domain = extract_url_features(user_url)
                
                if features is None:
                    st.error("❌ Invalid URL format. Please enter a valid URL.")
                else:
                    # Check if it's a known safe domain
                    is_known_safe = check_known_safe_domains(domain)
                    
                    # Calculate risk score using local algorithm
                    risk_score, reasons = calculate_risk_score(features)
                    
                    # Adjust score for known safe domains
                    if is_known_safe:
                        risk_score = max(0, risk_score - 30)
                        st.info(f"ℹ️ **{domain}** is a recognized safe domain")
                    
                    # Try API for ML model prediction (optional enhancement)
                    api_prediction = None
                    if api_online:
                        try:
                            api_result = predict_url_api(user_url)
                            if api_result:
                                api_prediction = api_result.get('label', None)
                                st.success("✅ ML Model API: Additional validation completed")
                        except:
                            pass
                    
                    # Update dashboard stats
                    label = "safe" if risk_score < 60 else "phishing"
                    update_dashboard_stats(label)
                    
                    # Display results
                    st.write("")
                    st.write(f"**🌐 Domain:** `{domain}`")
                    st.write(f"**🔒 Protocol:** `{parsed.scheme}`")
                    
                    # Risk score badge
                    if risk_score < 30:
                        color = "#00ff00"
                        bg_color = "rgba(0, 255, 0, 0.2)"
                        status = "LOW RISK"
                    elif risk_score < 60:
                        color = "#ffa500"
                        bg_color = "rgba(255, 165, 0, 0.2)"
                        status = "MEDIUM RISK"
                    else:
                        color = "#ff4d4d"
                        bg_color = "rgba(255, 0, 0, 0.2)"
                        status = "HIGH RISK"
                    
                    st.markdown(f"""
                    <div class='score-badge' style='background-color: {bg_color}; color: {color}; border: 2px solid {color};'>
                        Risk Score: {risk_score}/100 - {status}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Final verdict
                    if risk_score < 30:
                        st.markdown("<div class='result-box-safe'>🟢 ✔ SAFE — This URL appears safe to visit.</div>", 
                                   unsafe_allow_html=True)
                    elif risk_score < 60:
                        st.markdown("<div class='result-box-warning'>🟡 ⚠ CAUTION — This URL shows some suspicious characteristics. Proceed carefully.</div>", 
                                   unsafe_allow_html=True)
                    else:
                        st.markdown("<div class='result-box-danger'>🔴 ⚠ DANGER — This URL is likely phishing! Do not visit or enter personal information.</div>",
                                   unsafe_allow_html=True)
                    
                    # Add to scan history
                    st.session_state.scan_history.append({
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'type': 'url',
                        'result': label
                    })
                    
                    # Show API prediction if available
                    if api_prediction and api_prediction != label:
                        st.info(f"🤖 ML Model suggests: **{api_prediction.upper()}**")
                    # Show reasons if there are any
                    if reasons:
                        st.write("")
                        st.write("**🔍 Detection Details:**")
                        for reason in reasons:
                            st.write(f"  {reason}")
                    else:
                        st.write("")
                        st.success("✅ No suspicious patterns detected")
                    
                    # Technical details expander
                    with st.expander("📊 View Technical Analysis"):
                        st.write("**URL Features:**")
                        st.json({
                            "URL Length": features['url_length'],
                            "Domain Length": features['domain_length'],
                            "Subdomain Count": features['subdomain_count'],
                            "Dot Count": features['dot_count'],
                            "Uses HTTPS": features['is_https'],
                            "Has IP Address": features['has_ip'],
                            "Has @ Symbol": features['has_at'],
                            "Has Hyphen": features['has_hyphen'],
                            "Suspicious Keywords": features['suspicious_keywords'],
                            "Is URL Shortener": features['is_shortener'],
                            "Suspicious TLD": features['suspicious_tld']
                        })

# -------------------------------------
# TAB 2: EMAIL ANALYSIS
# -------------------------------------
elif st.session_state.active_tab == 1:
    st.subheader("📧 Email Analysis")

    email_text = st.text_area("✉️ Paste Email Content Here:", height=220)

    if st.button("Analyze Email", key="analyze_email_btn", type="primary"):
        if email_text.strip() == "":
            st.warning("⚠️ Please paste email content.")
        else:
            with st.spinner("🔍 Analyzing email..."):

                ml_prediction = None

                # Try backend API first
                if api_online:
                    api_result = predict_email_api(email_text)
                    if api_result:
                        ml_prediction = api_result.get("label", None)
                        st.success("🤖 ML Model Prediction Completed")

                # ---------------------------
                # FALLBACK: SIMPLE LOCAL EMAIL RULE CHECK
                # ---------------------------
                suspicious_patterns = [
                    "verify your account",
                    "login immediately",
                    "update your password",
                    "urgent action required",
                    "your account is locked",
                    "click the link below",
                    "confirm your identity",
                    "banking alert",
                    "unusual activity",
                    "payment failed",
                ]

                local_score = 0
                local_reasons = []

                lowered = email_text.lower()

                for p in suspicious_patterns:
                    if p in lowered:
                        local_score += 15
                        local_reasons.append(f"⚠️ Contains suspicious phrase: **'{p}'**")

                # Links inside email?
                urls_found = re.findall(r'https?://[^\s]+', email_text)
                if urls_found:
                    local_score += 20
                    local_reasons.append("⚠️ Contains external links")

                # Final local prediction
                if local_score < 30:
                    fallback_label = "safe"
                elif local_score < 60:
                    fallback_label = "warning"
                else:
                    fallback_label = "phishing"

                # Use ML model if available, else fallback
                final_label = ml_prediction if ml_prediction else fallback_label

                # Update dashboard stats
                st.session_state.emails_analyzed += 1

                # ---------------------------
                # DISPLAY RESULT
                #------------------------------
                if final_label == "safe":
                    st.markdown("<div class='result-box-safe'>🟢 SAFE — This email appears legitimate.</div>", unsafe_allow_html=True)
                elif final_label == "warning":
                    st.markdown("<div class='result-box-warning'>🟡 CAUTION — Email has suspicious elements.</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='result-box-danger'>🔴 DANGER — This email is likely phishing!</div>", unsafe_allow_html=True)

                # Show reasons for fallback
                if local_reasons:
                    st.write("**🔍 Analysis Details:**")
                    for r in local_reasons:
                        st.write(r)

                # Show extracted links
                if urls_found:
                    st.write("**🔗 Links Found in Email:**")
                    for link in urls_found:
                        st.write(f"- {link}")

                # Save to history
                st.session_state.scan_history.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "email",
                    "result": final_label
                })

# -------------------------------------
# TAB 3: SMS DETECTION
# -------------------------------------
elif st.session_state.active_tab == 2:
    st.subheader("📱 SMS Detection")

    sms_text = st.text_area("✉️ Enter SMS message text:", key="sms_input", height=180)

    if st.button("Analyze SMS", key="analyze_sms_btn", type="primary"):

        if sms_text.strip() == "":
            st.warning("⚠️ Please enter SMS text.")
        else:
            with st.spinner("🔍 Analyzing SMS..."):

                # ------------ API CALL (If online) -------------
                api_prediction = None
                if api_online:
                    try:
                        api_result = predict_sms_api(sms_text)
                        if api_result:
                            api_prediction = api_result.get("label", None)
                            st.success("🤖 AI Model Prediction Completed")
                    except:
                        pass

                # ------------ FALLBACK LOCAL CHECK -------------
                suspicious_keywords = [
                    "urgent", "verify", "confirm", "link", "click", "bank", "blocked",
                    "offer", "lottery", "free", "otp", "login", "password",
                    "account", "update", "refund", "payment", "win", "prize"
                ]

                score = 0
                reasons = []

                text_lower = sms_text.lower()

                # Keyword matching
                found_keywords = [w for w in suspicious_keywords if w in text_lower]
                score += len(found_keywords) * 5
                if found_keywords:
                    reasons.append(f"⚠️ Detected suspicious keywords: {', '.join(found_keywords)}")

                # Contains URL?
                url_pattern = r'https?://\S+|www\.\S+'
                has_url = bool(re.search(url_pattern, sms_text))
                if has_url:
                    score += 20
                    reasons.append("⚠️ Contains suspicious URL")

                # Threatening language
                threats = ["blocked", "suspended", "deactivated"]
                if any(t in text_lower for t in threats):
                    score += 15
                    reasons.append("🚨 Uses threatening language to create urgency")

                # Urgent tone
                urgent_words = ["urgent", "immediately", "now", "important"]
                if any(u in text_lower for u in urgent_words):
                    score += 10
                    reasons.append("⚠️ High urgency tone detected")

                # OTP request
                if "otp" in text_lower:
                    score += 10
                    reasons.append("🚨 Asking for OTP — common phishing tactic")

                # Cap score
                score = min(score, 100)

                # ------------ FINAL LABEL -------------
                if score < 30:
                    label = "safe"
                elif score < 60:
                    label = "suspicious"
                else:
                    label = "phishing"

                st.session_state.emails_analyzed += 1  # counting sms also

                # ------------ UI RESULT BOX -------------
                if score < 30:
                    st.markdown("<div class='result-box-safe'>🟢 This SMS appears **Safe**.</div>", unsafe_allow_html=True)
                elif score < 60:
                    st.markdown("<div class='result-box-warning'>🟡 This SMS is **Suspicious**. Be careful.</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='result-box-danger'>🔴 This SMS is **Likely Phishing**!</div>", unsafe_allow_html=True)

                # ------------ RISK SCORE BADGE -------------
                if score < 30:
                    color = "#00ff00"; bg = "rgba(0,255,0,0.2)"; status = "LOW RISK"
                elif score < 60:
                    color = "#ffa500"; bg = "rgba(255,165,0,0.2)"; status = "MEDIUM RISK"
                else:
                    color = "#ff4d4d"; bg = "rgba(255,0,0,0.2)"; status = "HIGH RISK"

                st.markdown(f"""
                <div class='score-badge' style='background-color:{bg}; color:{color}; border: 2px solid {color};'>
                    SMS Risk Score: {score}/100 — {status}
                </div>
                """, unsafe_allow_html=True)

                # ------------ AI MODEL DIFFERENCE -------------
                if api_prediction and api_prediction != label:
                    st.info(f"🤖 AI Model suggests: **{api_prediction.upper()}**")

                # ------------ DETAILS -------------
                if reasons:
                    st.write("### 🔍 Why this decision?")
                    for r in reasons:
                        st.write(r)

                with st.expander("📊 Technical Analysis"):
                    st.json({
                        "Suspicious Keywords Found": found_keywords,
                        "Contains URL": has_url,
                        "Urgent Language": any(u in text_lower for u in urgent_words),
                        "Threatening Language": any(t in text_lower for t in threats),
                        "OTP Mentioned": "otp" in text_lower,
                        "Final Risk Score": score
                    })

# ------------------- PRIVACY GUARD PAGE -------------------
elif st.session_state.active_tab == 3:
    st.subheader("🔐 Privacy Guard")

    st.write("Protect your personal data and online privacy. Enter a URL or text to scan for privacy risks.")

    # Input for URL or text
    pg_input = st.text_area("🔎 Enter URL, Email, or Text:", height=180, key="privacy_input")

    if st.button("Scan Privacy", key="privacy_scan_btn", type="primary"):
        if pg_input.strip() == "":
            st.warning("⚠️ Please enter content to scan.")
        else:
            with st.spinner("🔍 Scanning for privacy risks..."):

                # Simple Privacy Checks (Fallback)
                issues = []

                # Check for tracking parameters in URL
                if pg_input.startswith("http"):
                    if "utm_" in pg_input or "track" in pg_input or "ref=" in pg_input:
                        issues.append("⚠️ URL contains tracking parameters (utm_, ref=, track)")

                    # Check if the domain is safe
                    _, _, domain = extract_url_features(pg_input)
                    if domain and check_known_safe_domains(domain):
                        issues.append(f"✅ Domain '{domain}' is recognized as safe")
                    else:
                        issues.append(f"⚠️ Domain '{domain}' may be unknown or risky")

                # Check for email/phone exposure
                emails_found = re.findall(r'\b[\w.-]+?@\w+?\.\w+?\b', pg_input)
                phones_found = re.findall(r'\b\d{10,15}\b', pg_input)
                if emails_found:
                    issues.append(f"⚠️ Email(s) exposed: {', '.join(emails_found)}")
                if phones_found:
                    issues.append(f"⚠️ Phone number(s) exposed: {', '.join(phones_found)}")

                # Check for sensitive keywords
                sensitive_keywords = ["password", "ssn", "credit card", "dob"]
                found_sensitive = [w for w in sensitive_keywords if w in pg_input.lower()]
                if found_sensitive:
                    issues.append(f"⚠️ Sensitive keywords found: {', '.join(found_sensitive)}")

                # Display Results
                if not issues:
                    st.markdown("<div class='result-box-safe'>🟢 No major privacy issues detected!</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='result-box-warning'>🟡 Privacy issues detected:</div>", unsafe_allow_html=True)
                    for i in issues:
                        st.write(f"- {i}")

                # Optional: Summary Badge
                risk_score = min(len(issues)*20, 100)
                if risk_score < 30:
                    color = "#00ff00"; bg = "rgba(0,255,0,0.2)"; status = "LOW RISK"
                elif risk_score < 60:
                    color = "#ffa500"; bg = "rgba(255,165,0,0.2)"; status = "MEDIUM RISK"
                else:
                    color = "#ff4d4d"; bg = "rgba(255,0,0,0.2)"; status = "HIGH RISK"

                st.markdown(f"""
                <div class='score-badge' style='background-color:{bg}; color:{color}; border: 2px solid {color};'>
                    Privacy Risk Score: {risk_score}/100 — {status}
                </div>
                """, unsafe_allow_html=True)

                # Technical details expander
                with st.expander("📊 View Detailed Privacy Analysis"):
                    st.json({
                        "Tracking Parameters Detected": "utm_/track/ref" in pg_input,
                        "Emails Found": emails_found,
                        "Phone Numbers Found": phones_found,
                        "Sensitive Keywords Found": found_sensitive,
                        "Privacy Risk Score": risk_score
                    })


# -------------------------------------
# SCAN HISTORY
# -------------------------------------
if st.session_state.scan_history:
    with st.expander("📜 View Scan History (Last 10 Scans)"):
        st.write("**Recent Activity:**")
        for scan in reversed(st.session_state.scan_history[-10:]):
            result_emoji = "🟢" if scan['result'] in ['safe', 0] else "🔴"
            scan_type = scan.get('type', 'url').upper()
            st.write(f"{result_emoji} **{scan_type}** | {scan['timestamp']} | Result: {scan['result']}")

# -------------------------------------
# SECURITY TIPS
# -------------------------------------
st.write("---")
st.subheader("🔐 Quick Security Tips")

st.markdown("""
✔ Never click unknown short links (bit.ly, tinyurl).  
✔ Check for spelling errors in domain names.  
✔ Do not enter personal info on suspicious websites.  
✔ Avoid downloading email attachments from strangers.  
✔ Always use 2-Factor Authentication.  
✔ Look for HTTPS and the padlock icon in your browser.  
✔ Be suspicious of URLs with excessive subdomains or hyphens.  
✔ Verify the sender before clicking any links in emails.  
""")

# -------------------------------------
# FOOTER
# -------------------------------------
st.markdown("<div class='footer'>🛡️ Phishing Detection AI • Secure Your Digital Life</div>",
            unsafe_allow_html=True) 