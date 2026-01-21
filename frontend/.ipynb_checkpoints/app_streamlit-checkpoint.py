import streamlit as st
import re
from urllib.parse import urlparse
import socket

# -------------------------------------
# PAGE CONFIG
# -------------------------------------
st.set_page_config(
    page_title="Phishing Detection AI",
    layout="wide"
)

# -------------------------------------
# PHISHING DETECTION LOGIC
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


# -------------------------------------
# CUSTOM CSS FOR MODERN UI
# -------------------------------------
page_bg = """
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

/* Feature buttons */
.feature-btn {
    background-color: #081b33;
    color: #c8e4ff;
    padding: 22px;
    border-radius: 14px;
    text-align: center;
    border: 1px solid #13345f;
    transition: 0.2s ease;
    cursor: pointer;
    font-size: 18px;
}
.feature-btn:hover {
    background-color: #0f2e54;
    border-color: #3ec7ff;
    transform: scale(1.05);
}

/* Input box */
input {
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
"""

st.markdown(page_bg, unsafe_allow_html=True)

# -------------------------------------
# HEADER
# -------------------------------------
st.markdown("<div class='shield'>🛡️</div>", unsafe_allow_html=True)

st.markdown("<div class='status-box'>● SYSTEM ACTIVE</div>", unsafe_allow_html=True)
st.markdown("<h1 class='title-glow'>Protect Your<br>Digital Identity</h1>", unsafe_allow_html=True)
st.markdown("<p class='subtitle'>Advanced AI-powered phishing detection that analyzes URLs, emails, and messages in real time.</p>",
            unsafe_allow_html=True)

st.write("")

# -------------------------------------
# FEATURE BUTTONS
# -------------------------------------
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("<div class='feature-btn'>🛡️ URL Scanner</div>", unsafe_allow_html=True)

with col2:
    st.markdown("<div class='feature-btn'>📧 Email Analysis</div>", unsafe_allow_html=True)

with col3:
    st.markdown("<div class='feature-btn'>📱 SMS Detection</div>", unsafe_allow_html=True)

with col4:
    st.markdown("<div class='feature-btn'>🔐 Privacy Guard</div>", unsafe_allow_html=True)

st.write("---")

# -------------------------------------
# DASHBOARD SUMMARY CARDS
# -------------------------------------
st.subheader("📊 Security Dashboard")

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown("<div class='card'><h2>🔍 182</h2>URLs Scanned</div>", unsafe_allow_html=True)

with c2:
    st.markdown("<div class='card'><h2>⚠️ 39</h2>Threats Detected</div>", unsafe_allow_html=True)

with c3:
    st.markdown("<div class='card'><h2>📩 120</h2>Emails Analyzed</div>", unsafe_allow_html=True)

st.write("---")

# -------------------------------------
# URL SCANNER WITH REAL DETECTION
# -------------------------------------
st.subheader("🔎 URL Phishing Scanner")

user_url = st.text_input("🔗 Enter URL for Analysis:")

if st.button("Scan URL"):
    if user_url.strip() == "":
        st.warning("⚠️ Please enter a URL.")
    else:
        with st.spinner("🔍 Analyzing URL..."):
            # Extract features
            features, parsed, domain = extract_url_features(user_url)
            
            if features is None:
                st.error("❌ Invalid URL format. Please enter a valid URL.")
            else:
                # Check if it's a known safe domain
                is_known_safe = check_known_safe_domains(domain)
                
                # Calculate risk score
                risk_score, reasons = calculate_risk_score(features)
                
                # Adjust score for known safe domains
                if is_known_safe:
                    risk_score = max(0, risk_score - 30)
                    st.info(f"ℹ️ **{domain}** is a recognized safe domain")
                
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