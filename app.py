import requests
from datetime import datetime
from flask import Flask, jsonify, render_template, request, session
from flask_cors import CORS
import os
import PiTrustScorer
from flask_session import Session
from hf import generate_wallet_summary
import secrets
import string
import sqlite3
from datetime import datetime, timedelta
import json

apikey = os.getenv("apikey")

header = {
    'Authorization': f"Key {apikey}"
}

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True  # if HTTPS

@app.before_request
def make_session_non_permanent():
    session.permanent = False

@app.before_request
def log_request_info():
    print("➡️ Incoming request path:", request.path)
    print("➡️ Full URL:", request.url)
    print("➡️ Method:", request.method)


Session(app)
CORS(app)

# Flask API
pi_trust = PiTrustScorer.PiTrustScorer()

# Database setup
def get_db_connection():
    conn = sqlite3.connect('pitrust.db')
    conn.row_factory = sqlite3.Row
    return conn


# Plan configurations
PLAN_CONFIGS = {
    "starter": {"name": "Starter Plan", "price": 25, "duration_days": 30, "max_api_keys": 1, "max_requests": 500},
    "growth": {"name": "Growth Plan", "price": 50, "duration_days": 30, "max_api_keys": 3, "max_requests": 5000},
    "professional": {"name": "Professional Plan", "price": 100, "duration_days": 30, "max_api_keys": 10, "max_requests": 20000}
}

print(app.url_map)

def get_user_id():
    user_data = session.get("user")
    if user_data and "uid" in user_data:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE pi_uid = ?", (user_data["uid"],))
        # cursor.execute("SELECT id FROM users WHERE id = 2")
        user = cursor.fetchone()
        
        if user:
            conn.close()
            return user[0]
        else:
            cursor.execute(
                "INSERT INTO users (pi_uid, username) VALUES (?, ?)",
                (user_data["uid"], user_data.get("username", "Unknown"))
            )
            new_user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return new_user_id
    return None

@app.route("/api/plans/my", methods=["GET"])
def get_user_plans():
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get plans owned by the user
    cursor.execute("""
        SELECT p.*, COALESCE(SUM(ak.usage_count), 0) as total_usage, 'owner' as access_role, NULL as owner_username
        FROM plans p
        LEFT JOIN apikeys ak ON p.id = ak.plan_id
        WHERE p.user_id = ? 
        GROUP BY p.id
    """, (user_id,))
    
    owned_plans = []
    for row in cursor.fetchall():
        plan = dict(row)
        if plan["price"]:
            plan["price"] = float(plan["price"])
        owned_plans.append(plan)
    
    # Get plans shared with the user, including owner username
    cursor.execute("""
        SELECT p.*, COALESCE(SUM(ak.usage_count), 0) as total_usage, ps.role as access_role, u.username as owner_username
        FROM plans p
        JOIN plan_shares ps ON p.id = ps.plan_id
        LEFT JOIN apikeys ak ON p.id = ak.plan_id
        LEFT JOIN users u ON p.user_id = u.id
        WHERE ps.shared_with_username = (SELECT username FROM users WHERE id = ?)
        AND p.status = 'active'
        GROUP BY p.id
    """, (user_id,))
    
    shared_plans = []
    for row in cursor.fetchall():
        plan = dict(row)
        if plan["price"]:
            plan["price"] = float(plan["price"])
        shared_plans.append(plan)
    
    # Combine both lists
    all_plans = owned_plans + shared_plans
    
    # Sort by creation date (most recent first)
    all_plans.sort(key=lambda x: x['created_at'], reverse=True)
    
    conn.close()
    return jsonify(all_plans)

@app.route("/api/plans/activate", methods=["POST"])
def activate_plan():
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    data = request.get_json()
    plan_id = data.get("plan_id")
    txid = data.get("txid")
    
    if not plan_id or not txid:
        return jsonify({"error": "Missing plan_id or txid"}), 400
    
    if plan_id not in PLAN_CONFIGS:
        return jsonify({"error": "Invalid plan ID"}), 400
    
    plan_info = PLAN_CONFIGS[plan_id]
    start_date = datetime.now()
    end_date = start_date + timedelta(days=plan_info["duration_days"])
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO plans (user_id, tier, price, status, start_date, end_date, payment_txid, requests)
            VALUES (?, ?, ?, 'active', ?, ?, ?, ?)
        """, (
            user_id,
            plan_info["name"], 
            plan_info["price"], 
            start_date, 
            end_date, 
            txid, 
            plan_info["max_requests"]
        ))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Plan activated successfully"})
    
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

def decrement_plan_requests(plan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE plans
        SET requests = requests - 1
        WHERE id = ? AND requests > 0
    """, (plan_id,))
    conn.commit()
    conn.close()

def log_request(plan_id, wallet_address, api_key, response_time, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO requests (plan_id, wallet_address, api_key, response_time, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (plan_id, wallet_address, api_key, response_time, status, datetime.now()))
    conn.commit()
    conn.close()

@app.route("/api/plans/<int:plan_id>/requests", methods=["GET"])
def get_plan_requests(plan_id):
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's pi_uid for shared plan check
    cursor.execute("SELECT pi_uid FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    pi_uid = user[0]
    
    # Check if user has access to this plan (either owner or shared)
    cursor.execute("""
        SELECT p.id, p.user_id, ps.role 
        FROM plans p 
        LEFT JOIN plan_shares ps ON p.id = ps.plan_id AND ps.shared_with_username = ?
        WHERE p.id = ? AND (p.user_id = ? OR ps.role IS NOT NULL)
    """, (pi_uid, plan_id, user_id))
    
    plan_access = cursor.fetchone()
    if not plan_access:
        conn.close()
        return jsonify({"error": "Plan not found or access denied"}), 404
    
    cursor.execute("""
        SELECT * FROM requests 
        WHERE plan_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    """, (plan_id,))
    
    requests = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(requests)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/tou")
def tou():
    return render_template("tou.html")

@app.route("/pp")
def pp():
    return render_template("pp.html")

@app.route("/trust")
def wallet():
    return render_template("trust.html")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

def verify_pi_token(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    res = requests.get("https://api.minepi.com/v2/me", headers=headers)
    if res.status_code == 200:
        return res.json()
    return None

@app.route("/api/store-token", methods=["POST"])
def store_token():
    data = request.get_json()
    access_token = data.get("accessToken")
    
    if not access_token:
        return jsonify({"error": "No token provided"}), 400

    user_data = verify_pi_token(access_token)
    if not user_data:
        return jsonify({"error": "Invalid token"}), 401

    session["access_token"] = access_token
    return jsonify({"success": True})

@app.route("/api/verify-auth", methods=["POST"])
def verify_auth():
    user_data = verify_pi_token(session.get("access_token"))
    if user_data:
        session["user"] = {
            "uid": user_data.get("uid"),
            "username": user_data.get("username")
        }
        return jsonify({"success": True, "user": session["user"]})
    return jsonify({"error": "Invalid token"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"success": True})

@app.route('/api/pi-trust/<wallet_id>', methods=['GET'])
def get_pi_trust_score(wallet_id):
    api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization')
    
    if api_key and api_key.startswith('Bearer '):
        api_key = api_key[7:]
    
    if not api_key:
        return jsonify({"error": "API key required"}), 401
    
    key_info = validate_api_key(api_key)
    if not key_info:
        return jsonify({"error": "Invalid API key"}), 401
    
    if key_info["plan_status"] != "active":
        return jsonify({"error": "Plan is not active"}), 403
    
    if key_info["plan_requests"] <= 0:
        return jsonify({"error": "Monthly request limit exceeded"}), 429
    
    start_time = datetime.now()
    
    try:
        result = pi_trust.calculate_pi_trust(wallet_id)
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        
        increment_api_usage(key_info["api_key_id"])
        decrement_plan_requests(key_info["plan_id"])
        log_request(key_info["plan_id"], wallet_id, api_key, int(response_time), "success")
        
        try:
            result["breakdown"] = generate_wallet_summary(result)
        except Exception as e:
            result["breakdown"] = f"Could not generate summary. Raw score: {result['pi_trust_score']}."
        
        return jsonify(result)
        
    except Exception as e:
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        log_request(key_info["plan_id"], wallet_id, api_key, int(response_time), "error")
        return jsonify({"error": f"Trust score calculation failed: {str(e)}"}), 500

def generate_api_key(key_type="live"):
    prefix = "pk_live_" if key_type == "live" else "pk_test_"
    random_part = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    return prefix + random_part

@app.route("/api/apikeys", methods=["GET"])
def get_api_keys():
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ak.id, ak.api_key, ak.usage_count, ak.created_at, ak.last_used,
               p.tier, p.id as plan_id, p.status
        FROM apikeys ak
        JOIN plans p ON ak.plan_id = p.id
        WHERE p.user_id = ? AND p.status = 'active'
        ORDER BY ak.created_at DESC
    """, (user_id,))
    
    api_keys = []
    for row in cursor.fetchall():
        api_keys.append(dict(row))
    
    conn.close()
    return jsonify(api_keys)

@app.route("/api/apikeys", methods=["POST"])
def create_api_key():
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    data = request.get_json()
    plan_id = data.get("plan_id")
    key_name = data.get("key_name", "API Key")
    key_type = data.get("key_type", "live")
    
    if not plan_id:
        return jsonify({"error": "Plan ID is required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's pi_uid and username for shared plan check
    cursor.execute("SELECT pi_uid, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    pi_uid = user[0]
    username = user[1]
    
    try:
        # Check if user has access and permission to create API keys
        cursor.execute("""
            SELECT p.id, p.user_id, p.tier, p.status, ps.role 
            FROM plans p 
            LEFT JOIN plan_shares ps ON p.id = ps.plan_id 
                AND (ps.shared_with_username = ? OR ps.shared_with_username = ?)
            WHERE p.id = ? AND (p.user_id = ? OR ps.role = 'editor')
        """, (pi_uid, username, plan_id, user_id))
        
        plan = cursor.fetchone()
        if not plan:
            return jsonify({"error": "Plan not found or insufficient permissions. Only owners and editors can create API keys."}), 404
        
        # Check if plan is active
        if plan[3] != 'active':
            return jsonify({"error": "Plan is not active"}), 400
        
        is_owner = plan[1] == user_id
        shared_role = plan[4]
        
        # Only owners and editors can create API keys
        if not is_owner and shared_role != 'editor':
            return jsonify({"error": "Insufficient permissions to create API keys. Only owners and editors can create API keys."}), 403
        
        plan_tier = plan[2].lower().split()[0]
        
        if plan_tier not in PLAN_CONFIGS:
            return jsonify({"error": "Invalid plan tier"}), 400
        
        max_keys = PLAN_CONFIGS[plan_tier]["max_api_keys"]
        
        cursor.execute("SELECT COUNT(*) FROM apikeys WHERE plan_id = ?", (plan_id,))
        current_key_count = cursor.fetchone()[0]
        
        if current_key_count >= max_keys:
            return jsonify({
                "error": f"Maximum API keys reached for {plan_tier} plan ({max_keys} keys)"
            }), 400
        
        new_api_key = generate_api_key(key_type)
        
        cursor.execute("""
            INSERT INTO apikeys (plan_id, api_key, created_at)
            VALUES (?, ?, ?)
        """, (plan_id, new_api_key, datetime.now()))
        
        api_key_id = cursor.lastrowid
        conn.commit()
        
        result = {
            "id": api_key_id,
            "api_key": new_api_key,
            "plan_id": plan_id,
            "usage_count": 0,
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "name": key_name
        }
        
        conn.close()
        return jsonify(result), 201
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

@app.route("/api/apikeys/<int:api_key_id>", methods=["DELETE"])
def revoke_api_key(api_key_id):
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's pi_uid and username for shared plan check
    cursor.execute("SELECT pi_uid, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    pi_uid = user[0]
    username = user[1]
    
    try:
        # Check if user has permission to delete this API key
        cursor.execute("""
            SELECT ak.id, p.user_id, ps.role 
            FROM apikeys ak
            JOIN plans p ON ak.plan_id = p.id
            LEFT JOIN plan_shares ps ON p.id = ps.plan_id 
                AND (ps.shared_with_username = ? OR ps.shared_with_username = ?)
            WHERE ak.id = ? AND (p.user_id = ? OR ps.role = 'editor')
        """, (pi_uid, username, api_key_id, user_id))
        
        api_key = cursor.fetchone()
        if not api_key:
            return jsonify({"error": "API key not found or insufficient permissions. Only owners and editors can revoke API keys."}), 404
        
        cursor.execute("DELETE FROM apikeys WHERE id = ?", (api_key_id,))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "API key revoked successfully"})
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
        
@app.route("/api/plans/<int:plan_id>/apikeys", methods=["GET"])
def get_plan_api_keys(plan_id):
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's pi_uid and username for shared plan check
    cursor.execute("SELECT pi_uid, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    pi_uid = user[0]
    username = user[1]
    
    # Check if user has access to this plan (owner, editor, or viewer)
    cursor.execute("""
        SELECT p.id, p.user_id, ps.role 
        FROM plans p 
        LEFT JOIN plan_shares ps ON p.id = ps.plan_id 
            AND (ps.shared_with_username = ? OR ps.shared_with_username = ?)
        WHERE p.id = ? AND (p.user_id = ? OR ps.role IS NOT NULL)
    """, (pi_uid, username, plan_id, user_id))
    
    plan_access = cursor.fetchone()
    if not plan_access:
        conn.close()
        return jsonify({"error": "Plan not found or access denied"}), 404
    
    is_owner = plan_access[1] == user_id
    user_role = plan_access[2] if plan_access[2] else 'owner'
    
    # Owners, editors, and viewers can all see API keys
    # (editors can also create/revoke, viewers are read-only)
    
    # Fetch API keys
    cursor.execute("""
        SELECT id, api_key, usage_count, created_at, last_used
        FROM apikeys WHERE plan_id = ?
        ORDER BY created_at DESC
    """, (plan_id,))
    
    api_keys = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(api_keys)
def validate_api_key(api_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ak.id, ak.plan_id, ak.usage_count, p.tier, p.status, p.requests
        FROM apikeys ak
        JOIN plans p ON ak.plan_id = p.id
        WHERE ak.api_key = ? AND p.status = 'active'
    """, (api_key,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return {
            "api_key_id": result[0],
            "plan_id": result[1],
            "usage_count": result[2],
            "plan_tier": result[3],
            "plan_status": result[4],
            "plan_requests": result[5]
        }
    return None

def increment_api_usage(api_key_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE apikeys 
        SET usage_count = usage_count + 1, last_used = ?
        WHERE id = ?
    """, (datetime.now(), api_key_id))
    conn.commit()
    conn.close()

# Add these endpoints to your app.py

@app.route("/api/plans/<int:plan_id>/shares", methods=["GET"])
def get_plan_shares(plan_id):
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify plan belongs to user
    cursor.execute("SELECT id FROM plans WHERE id = ? AND user_id = ?", (plan_id, user_id))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Plan not found"}), 404
    
    cursor.execute("""
        SELECT ps.*, u.username as shared_with_username_display
        FROM plan_shares ps
        LEFT JOIN users u ON u.pi_uid = ps.shared_with_username
        WHERE ps.plan_id = ?
        ORDER BY ps.shared_at DESC
    """, (plan_id,))
    
    shares = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(shares)

@app.route("/api/plans/<int:plan_id>/shares", methods=["POST"])
def add_plan_share(plan_id):
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    data = request.get_json()
    username = data.get("username")
    role = data.get("role", "viewer")
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    if role not in ["viewer", "editor"]:
        return jsonify({"error": "Invalid role"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify plan belongs to user and check share limits
        cursor.execute("""
            SELECT p.*, COUNT(ps.id) as current_shares 
            FROM plans p 
            LEFT JOIN plan_shares ps ON p.id = ps.plan_id 
            WHERE p.id = ? AND p.user_id = ?
            GROUP BY p.id
        """, (plan_id, user_id))
        
        plan = cursor.fetchone()
        if not plan:
            return jsonify({"error": "Plan not found"}), 404
        
        # Check if user exists in our system
        cursor.execute("SELECT id FROM users WHERE username = ? OR pi_uid = ?", (username, username))
        shared_user = cursor.fetchone()
        
        if not shared_user:
            return jsonify({"error": "User not found in PiTrust system"}), 404
        
        # Check if already shared
        cursor.execute("SELECT id FROM plan_shares WHERE plan_id = ? AND shared_with_username = ?", 
                      (plan_id, username))
        if cursor.fetchone():
            return jsonify({"error": "Plan already shared with this user"}), 400
        
        # Check share limits based on plan tier
        plan_tier = plan["tier"].lower().split()[0]
        max_shares = {
            "starter": 1,
            "growth": 3,
            "professional": 10
        }.get(plan_tier, 1)
        
        if plan["current_shares"] >= max_shares:
            return jsonify({
                "error": f"Maximum shares reached for {plan_tier} plan ({max_shares} shares)"
            }), 400
        
        # Add share
        cursor.execute("""
            INSERT INTO plan_shares (plan_id, shared_with_username, role, shared_at)
            VALUES (?, ?, ?, ?)
        """, (plan_id, username, role, datetime.now()))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Plan shared successfully"})
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

@app.route("/api/plans/<int:plan_id>/shares/<int:share_id>", methods=["DELETE"])
def remove_plan_share(plan_id, share_id):
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify plan belongs to user
        cursor.execute("SELECT id FROM plans WHERE id = ? AND user_id = ?", (plan_id, user_id))
        if not cursor.fetchone():
            return jsonify({"error": "Plan not found"}), 404
        
        # Verify share exists for this plan
        cursor.execute("SELECT id FROM plan_shares WHERE id = ? AND plan_id = ?", (share_id, plan_id))
        if not cursor.fetchone():
            return jsonify({"error": "Share not found"}), 404
        
        cursor.execute("DELETE FROM plan_shares WHERE id = ?", (share_id,))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Share removed successfully"})
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

@app.route('/payment/approve', methods=['POST'])
def approve():
    try:
        data = request.get_json()
        if not data:
            return jsonify(status="error", message="No JSON data provided"), 400
            
        paymentId = data.get("paymentId")
        if not paymentId:
            return jsonify(status="error", message="Missing paymentId"), 400

        approveurl = f"https://api.minepi.com/v2/payments/{paymentId}/approve"
        response = requests.post(approveurl, headers=header)

        if response.status_code == 200:
            return jsonify(status="ok", message="Payment approved"), 200
        else:
            return jsonify(status="error", message="Pi API approval failed", details=response.text), response.status_code

    except Exception as e:
        return jsonify(status="error", message=str(e)), 500

@app.route('/payment/complete', methods=['POST'])
def complete():
    try:
        data = request.get_json()
        if not data:
            return jsonify(status="error", message="No JSON data provided"), 400

        paymentId = data.get('paymentId')
        txid = data.get('txid')

        if not paymentId or not txid:
            return jsonify(status="error", message="Missing paymentId or txid"), 400

        completeurl = f"https://api.minepi.com/v2/payments/{paymentId}/complete"
        complete_data = {'txid': txid}

        response = requests.post(
            completeurl,
            headers={**header, 'Content-Type': 'application/json'},
            json=complete_data
        )

        if response.status_code == 200:
            try:
                payment_data = response.json()
                wallet_id = payment_data.get("metadata", {}).get("walletAddress")
                if not wallet_id:
                    return jsonify(status="error", message="No walletAddress in metadata"), 400

                result = pi_trust.calculate_pi_trust(wallet_id)
                return jsonify(
                    status="ok",
                    message="Payment completed and trust score calculated",
                    wallet_id=wallet_id,
                    trust_result=result
                ), 200
            except json.JSONDecodeError:
                return jsonify(status="ok", message="Payment completed (no data)"), 200
        else:
            return jsonify(status="error", message="Pi API completion failed", details=response.text), response.status_code

    except Exception as e:
        return jsonify(status="error", message=str(e)), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "PiTrust API"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)



