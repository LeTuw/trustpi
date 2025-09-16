import requests
from datetime import datetime
from flask import Flask, jsonify,render_template, request, session
from flask_cors import CORS
import requests
import os
import PiTrustScorer
from flask_session import Session
from hf import generate_wallet_summary

apikey = os.getenv("apikey")

header = {
    'Authorization': f"Key {apikey}"
}


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True  # if HTTPS


Session(app)
CORS(app)


# Flask API
pi_trust = PiTrustScorer.PiTrustScorer()

@app.route("/")
def index():
    return render_template("index.html")

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
    """Check token with Pi API"""
    headers = {"Authorization": f"Bearer {access_token}"}
    res = requests.get("https://api.minepi.com/v2/me", headers=headers)
    if res.status_code == 200:
        return res.json()
    return None


# -----------------------------
# Check if user has active session
# -----------------------------
@app.route("/api/store-token", methods=["POST"])
def store_token():
    """Receive accessToken from frontend, verify, and store in session"""
    data = request.get_json()
    access_token = data.get("accessToken")
    
    if not access_token:
        return jsonify({"error": "No token provided"}), 400

    # Verify token with Pi API
    user_data = verify_pi_token(access_token)
    if not user_data:
        return jsonify({"error": "Invalid token"}), 401

    # Only save token in session
    session["access_token"] = access_token

    return jsonify({"success": True})
# -----------------------------
# Verify authResult from frontend
# -----------------------------
@app.route("/api/verify-auth", methods=["POST"])
def verify_auth():
    user_data = verify_pi_token(session.get("access_token"))
    print(user_data)
    if user_data:
        # Save user in session
        session["user"] = {
            "uid": user_data.get("uid"),
            "username": user_data.get("username")
        }
        return jsonify({"success": True, "user": session["user"]})
    return jsonify({"error": "Invalid token"}), 401

# -----------------------------
# Logout
# -----------------------------
@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"success": True})
    

@app.route('/api/pi-trust/<wallet_id>', methods=['GET'])
def get_pi_trust_score(wallet_id):
    result = pi_trust.calculate_pi_trust(wallet_id)
    
    text = f"""
    Wallet {wallet_id} trust score: {result['pi_trust_score']}/1000.
    Components:
    - Payment reliability: {result['components']['payment_reliability']}
    - Account tenure: {result['components']['account_tenure']}
    - Network strength: {result['components']['network_strength']}
    - Balance health: {result['components']['balance_health']}
    - On-chain attestations: {result['components']['onchain_attestations']}
    """

    try:
        # Generate NLP summary
        result["breakdown"] = generate_wallet_summary(result)
    except Exception as e:
        # fallback if Hugging Face API fails
        result["breakdown"] = f"Could not generate summary. Raw score: {result['pi_trust_score']}."

    return jsonify(result)


@app.route('/payment/approve', methods=['POST'])
def approve():
    try:
        # Read JSON data from frontend
        data = request.get_json()
        
        if not data:
            return jsonify(status="error", message="No JSON data provided"), 400
            
        paymentId = data.get("paymentId")
        
        if not paymentId:
            return jsonify(status="error", message="Missing paymentId"), 400

        print(f"Approving payment: {paymentId}")

        # Approve the payment using your server key
        approveurl = f"https://api.minepi.com/v2/payments/{paymentId}/approve"
        response = requests.post(approveurl, headers=header)

        print(f"Pi API approve response: {response.status_code} - {response.text}")

        # Check if Pi API request was successful
        if response.status_code == 200:
            return jsonify(status="ok", message="Payment approved"), 200
        else:
            print(f"Pi API error: {response.text}")
            return jsonify(status="error", message="Pi API approval failed", details=response.text), response.status_code

    except requests.exceptions.RequestException as e:
        print(f"Network error during approve: {e}")
        return jsonify(status="error", message="Network error"), 500
    except Exception as e:
        print(f"Approve endpoint error: {e}")
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

        print(f"Completing payment: {paymentId} with txid: {txid}")

        completeurl = f"https://api.minepi.com/v2/payments/{paymentId}/complete"
        complete_data = {'txid': txid}

        response = requests.post(
            completeurl,
            headers={**header, 'Content-Type': 'application/json'},
            json=complete_data
        )

        print(f"Pi API complete response: {response.status_code} - {response.text}")

        if response.status_code == 200:
            try:
                payment_data = response.json()

                # ✅ get the wallet from payment metadata
                wallet_id = payment_data.get("metadata", {}).get("walletAddress")
                if not wallet_id:
                    return jsonify(status="error", message="No walletAddress in metadata"), 400

                # 🔒 run your private calculation
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
            print(f"Pi API complete error: {response.text}")
            return jsonify(
                status="error",
                message="Pi API completion failed",
                details=response.text
            ), response.status_code

    except requests.exceptions.RequestException as e:
        print(f"Network error during complete: {e}")
        return jsonify(status="error", message="Network error"), 500
    except Exception as e:
        print(f"Complete endpoint error: {e}")
        return jsonify(status="error", message=str(e)), 500


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "PiTrust API"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)