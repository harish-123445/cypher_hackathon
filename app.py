import os
import json
import logging
import threading
from enum import Enum
from decimal import Decimal, getcontext
from typing import Optional, Dict, Any
from datetime import datetime
import hashlib
import time
import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_account import Account
from eth_account.messages import encode_defunct
import smtplib
from email.message import EmailMessage
import random

from utils import (
    create_wallet_in_db,
    get_wallet,
    update_wallet_balance,
    save_transaction,
    list_transactions_for_address,
    eth_to_wei,
    wei_to_eth,
)

# Enums
class AmountMode(Enum):
    ETH = "ETH"
    USD = "USD"

class NotificationType(Enum):
    EMAIL = "email"
    TELEGRAM = "telegram"

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wallet_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Set Decimal precision
getcontext().prec = 50

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SESSION_SECRET", os.urandom(24).hex())
CORS(app, resources={r"/api/*": {"origins": os.getenv("ALLOWED_ORIGINS", "*")}})

# Configuration class
class Config:
    def __init__(self):
        with open('config.json', 'r') as f:
            config = json.load(f)
        self.skip_url = config['skip_url']
        self.pending_tx_expiry = config['pending_tx_expiry']
        self.slippage_tolerance = config['slippage_tolerance']
        self.starting_balance_min = config['starting_balance_min']
        self.starting_balance_max = config['starting_balance_max']
        self.eth_chain_id = config['eth_chain_id']
        self.usdc_contract = config['usdc_contract']
        self.wallets_collection = config['wallets_collection']
        self.transactions_collection = config['transactions_collection']
        self.allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
        self.max_transfer_amount = config.get('max_transfer_amount', 1000.0)
        self.min_transfer_amount = config.get('min_transfer_amount', 0.0001)

# Initialize configuration
config = Config()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Temporary storage for pending transactions
pending_transactions: Dict[str, Dict[str, Any]] = {}

# ==================== HELPERS ====================

def validate_address(address: str) -> bool:
    """Validate Ethereum address format."""
    return isinstance(address, str) and len(address) == 42 and address.startswith('0x')

def validate_amount(amount: str) -> bool:
    """Validate amount format."""
    try:
        amount = Decimal(amount)
        return config.min_transfer_amount <= amount <= config.max_transfer_amount
    except (ValueError, TypeError):
        return False

def generate_mnemonic() -> str:
    """Generate a 12-word mnemonic phrase."""
    try:
        return Bip39MnemonicGenerator().FromWordsNumber(12).ToStr()
    except Exception as e:
        logger.error(f"Failed to generate mnemonic: {str(e)}")
        raise ValueError(f"Failed to generate mnemonic: {str(e)}")

def derive_eth_account_from_mnemonic(mnemonic: str, account_index: int = 0) -> tuple[Account, str]:
    """Derive Ethereum account from mnemonic phrase."""
    try:
        mnemonic = str(mnemonic).strip()
        if not mnemonic:
            raise ValueError("Mnemonic cannot be empty")
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        bip44_def = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        acct = bip44_def.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(account_index)
        priv_key = acct.PrivateKey().Raw().ToHex()
        acct_obj = Account.from_key(priv_key)
        return acct_obj, priv_key
    except Exception as e:
        logger.error(f"Failed to derive account from mnemonic: {str(e)}")
        raise ValueError(f"Failed to derive account: {str(e)}")

def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()

def quote_usd_to_eth(amount_usd: Decimal) -> Optional[Decimal]:
    """Get ETH equivalent using Skip API."""
    try:
        body = {
            "source_asset_denom": config.usdc_contract,
            "source_asset_chain_id": config.eth_chain_id,
            "dest_asset_denom": "ethereum-native",
            "dest_asset_chain_id": config.eth_chain_id,
            "amount_in": str(int(amount_usd * Decimal(10)**6)),
            "chain_ids_to_addresses": {config.eth_chain_id: "0x742d35Cc6634C0532925a3b8D4C9db96c728b0B4"},
            "slippage_tolerance_percent": str(config.slippage_tolerance),
            "smart_swap_options": {"evm_swaps": True},
            "allow_unsafe": False
        }
        r = requests.post(config.skip_url, json=body, timeout=8)
        r.raise_for_status()
        data = r.json()
        dest_amount_wei = int(data.get("route", {}).get("amount_out") or data.get("amount_out", 0))
        if not dest_amount_wei:
            logger.warning("No amount received from Skip API")
            return None
        return wei_to_eth(dest_amount_wei)
    except requests.RequestException as e:
        logger.error(f"Skip API request failed: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in quote_usd_to_eth: {str(e)}")
        return None

def sign_message_with_private_key(message: str, private_key_hex: str) -> str:
    """Sign a message with the private key."""
    try:
        acct = Account.from_key(private_key_hex)
        encoded = encode_defunct(text=message)
        signed = acct.sign_message(encoded)
        return signed.signature.hex()
    except Exception as e:
        logger.error(f"Failed to sign message: {str(e)}")
        raise ValueError(f"Failed to sign message: {str(e)}")

def verify_signed_message(message: str, signature_hex: str) -> str:
    """Verify a signed message."""
    try:
        encoded = encode_defunct(text=message)
        return Account.recover_message(encoded, signature=signature_hex)
    except Exception as e:
        logger.error(f"Failed to verify signed message: {str(e)}")
        raise ValueError(f"Failed to verify signed message: {str(e)}")

def send_notification(recipient: str, subject: str, body: str, notification_type: NotificationType) -> None:
    """Send notification via email or Telegram."""
    try:
        if notification_type == NotificationType.EMAIL:
            host = os.getenv("SMTP_HOST")
            port = int(os.getenv("SMTP_PORT", "587"))
            user = os.getenv("SMTP_USER")
            password = os.getenv("SMTP_PASSWORD")
            
            if not all([host, user, password]):
                logger.warning("SMTP not configured, skipping email")
                return
                
            msg = EmailMessage()
            msg["From"] = user
            msg["To"] = recipient
            msg["Subject"] = subject
            
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2>{subject}</h2>
                <p>{body}</p>
                <hr>
                <p style="font-size: small; color: #777;">This is a mock wallet notification.</p>
            </body>
            </html>
            """
            msg.set_content(body)
            msg.add_alternative(html_body, subtype='html')
            
            with smtplib.SMTP(host, port) as s:
                s.starttls()
                s.login(user, password)
                s.send_message(msg)
            logger.info(f"Email sent to {recipient}")
            
        elif notification_type == NotificationType.TELEGRAM:
            if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
                logger.warning("Telegram not configured, skipping notification")
                return
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            resp = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": body, "parse_mode": "HTML"}, timeout=5)
            resp.raise_for_status()
            logger.info("Telegram notification sent successfully")
            
    except Exception as e:
        logger.error(f"Failed to send {notification_type.value} notification to {recipient}: {str(e)}")

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/wallet/generate', methods=['POST'])
def generate_wallet():
    """Generate a new wallet."""
    try:
        data = request.json or {}
        email = data.get('email')
        
        if email and not isinstance(email, str):
            return jsonify({"error": "Invalid email format"}), 400
            
        mnemonic = generate_mnemonic()
        acct_obj, priv_key = derive_eth_account_from_mnemonic(mnemonic)
        address = acct_obj.address
        
        if not validate_address(address):
            return jsonify({"error": "Invalid address generated"}), 500
            
        if get_wallet(address):
            logger.warning(f"Wallet already exists for address: {address}")
            return jsonify({"error": "Wallet already exists"}), 400
        
        balance = Decimal(str(random.uniform(config.starting_balance_min, config.starting_balance_max))).quantize(Decimal("0.00000001"))
        create_wallet_in_db(
            address,
            hash_sensitive_data(mnemonic),
            hash_sensitive_data(priv_key),
            balance,
            email
        )
        
        send_notification(
            email,
            "Wallet Created",
            f"Your new wallet with address {address} has been created.",
            NotificationType.EMAIL
        )
        
        logger.info(f"Generated new wallet: {address}")
        return jsonify({
            "success": True,
            "address": address,
            "mnemonic": mnemonic,
            "private_key": priv_key
        })
    except Exception as e:
        logger.error(f"Error generating wallet: {str(e)}")
        return jsonify({"error": "Failed to generate wallet"}), 500

@app.route('/api/wallet/import', methods=['POST'])
def import_wallet():
    """Import an existing wallet from mnemonic."""
    try:
        data = request.json or {}
        mnemonic = data.get('mnemonic', '').strip()
        account_index = int(data.get('account_index', 0))
        email = data.get('email')
        
        if not mnemonic:
            logger.warning("Mnemonic not provided for wallet import")
            return jsonify({"error": "Mnemonic required"}), 400
            
        if not isinstance(account_index, int) or account_index < 0:
            return jsonify({"error": "Invalid account index"}), 400
            
        if email and not isinstance(email, str):
            return jsonify({"error": "Invalid email format"}), 400
            
        acct_obj, priv_key = derive_eth_account_from_mnemonic(mnemonic, account_index)
        address = acct_obj.address
        
        if not validate_address(address):
            return jsonify({"error": "Invalid address derived"}), 400
            
        existing = get_wallet(address)
        
        if existing:
            balance = wei_to_eth(int(existing['balance_wei']))
            logger.info(f"Imported existing wallet: {address}")
            return jsonify({
                "success": True,
                "address": address,
                "balance": str(balance),
                "existing": True,
                "private_key": priv_key
            })
        
        starting_balance = Decimal(str(random.uniform(config.starting_balance_min, config.starting_balance_max))).quantize(Decimal("0.00000001"))
        create_wallet_in_db(
            address,
            hash_sensitive_data(mnemonic),
            hash_sensitive_data(priv_key),
            starting_balance,
            email
        )
        
        send_notification(
            email,
            "Wallet Imported",
            f"Wallet with address {address} has been successfully imported.",
            NotificationType.EMAIL
        )
        
        logger.info(f"Imported new wallet: {address}")
        return jsonify({
            "success": True,
            "address": address,
            "balance": str(starting_balance),
            "existing": False,
            "private_key": priv_key
        })
    except Exception as e:
        logger.error(f"Error importing wallet: {str(e)}")
        return jsonify({"error": "Failed to import wallet"}), 500

@app.route('/api/wallet/<address>', methods=['GET'])
def get_wallet_info(address: str):
    """Get wallet information."""
    try:
        if not validate_address(address):
            return jsonify({"error": "Invalid address format"}), 400
            
        wallet = get_wallet(address)
        if not wallet:
            logger.warning(f"Wallet not found: {address}")
            return jsonify({"error": "Wallet not found"}), 404
            
        balance = wei_to_eth(int(wallet['balance_wei']))
        logger.info(f"Retrieved wallet info: {address}")
        return jsonify({
            "address": wallet['address'],
            "balance": str(balance),
            "created_at": wallet['created_at']['_seconds'],
            "email": wallet.get('notification_email')
        })
    except Exception as e:
        logger.error(f"Error retrieving wallet info for {address}: {str(e)}")
        return jsonify({"error": "Failed to retrieve wallet info"}), 500

@app.route('/api/transfer/prepare', methods=['POST'])
def prepare_transfer():
    """Prepare a transfer transaction."""
    try:
        data = request.json or {}
        sender = data.get('sender', '').strip().lower()
        recipient = data.get('recipient', '').strip().lower()
        amount_mode = data.get('amount_mode', AmountMode.ETH.value)
        amount_str = data.get('amount', '0')
        
        if not validate_address(sender) or not validate_address(recipient):
            logger.warning("Invalid sender or recipient address")
            return jsonify({"error": "Invalid sender or recipient address"}), 400
            
        if amount_mode not in [mode.value for mode in AmountMode]:
            return jsonify({"error": "Invalid amount mode"}), 400
            
        if not validate_amount(amount_str):
            logger.warning("Invalid transfer amount")
            return jsonify({"error": f"Amount must be between {config.min_transfer_amount} and {config.max_transfer_amount}"}), 400
        
        amount = Decimal(amount_str)
        sender_wallet = get_wallet(sender)
        if not sender_wallet:
            logger.warning(f"Sender wallet not found: {sender}")
            return jsonify({"error": "Sender wallet not found"}), 404
            
        sender_balance = wei_to_eth(int(sender_wallet['balance_wei']))
        
        if amount_mode == AmountMode.USD.value:
            eth_amount = quote_usd_to_eth(amount)
            if eth_amount is None:
                logger.error("Failed to get USD to ETH price quote")
                return jsonify({"error": "Failed to get price quote"}), 500
            usd_note = f" (${amount} USD)"
        else:
            eth_amount = amount
            usd_note = ""
        
        if eth_amount > sender_balance:
            logger.warning(f"Insufficient balance for {sender}: {eth_amount} > {sender_balance}")
            return jsonify({"error": "Insufficient balance"}), 400
        
        tx_id = hashlib.sha256(f"{sender}{recipient}{eth_amount}{time.time()}".encode()).hexdigest()[:16]
        message = f"Transfer {eth_amount} ETH{usd_note} to {recipient} from {sender}"
        
        pending_transactions[tx_id] = {
            "sender": sender,
            "recipient": recipient,
            "amount_eth": str(eth_amount),
            "amount_usd": str(amount) if amount_mode == AmountMode.USD.value else None,
            "message": message,
            "created_at": time.time(),
            "expires_at": time.time() + config.pending_tx_expiry
        }
        
        logger.info(f"Prepared transfer: {tx_id} from {sender} to {recipient}")
        return jsonify({
            "success": True,
            "tx_id": tx_id,
            "message": message,
            "eth_amount": str(eth_amount),
            "sender_balance": str(sender_balance)
        })
    except Exception as e:
        logger.error(f"Error preparing transfer: {str(e)}")
        return jsonify({"error": "Failed to prepare transfer"}), 500

@app.route('/api/transfer/execute', methods=['POST'])
def execute_transfer():
    """Execute a prepared transfer."""
    try:
        data = request.json or {}
        tx_id = data.get('tx_id')
        signature = data.get('signature')
        
        if not tx_id or not signature:
            logger.warning("Missing tx_id or signature in transfer execution")
            return jsonify({"error": "Transaction ID and signature required"}), 400
        
        pending_tx = pending_transactions.get(tx_id)
        if not pending_tx or time.time() > pending_tx['expires_at']:
            pending_transactions.pop(tx_id, None)
            logger.warning(f"Transaction not found or expired: {tx_id}")
            return jsonify({"error": "Transaction not found or expired"}), 404
        
        recovered_address = verify_signed_message(pending_tx['message'], signature)
        if recovered_address.lower() != pending_tx['sender']:
            logger.warning(f"Invalid signature for transaction: {tx_id}")
            return jsonify({"error": "Invalid signature"}), 403
        
        if pending_tx['amount_usd']:
            current_eth = quote_usd_to_eth(Decimal(pending_tx['amount_usd']))
            if current_eth is None:
                logger.error("Failed to verify current price for USD transfer")
                return jsonify({"error": "Failed to verify current price"}), 500
            original_eth = Decimal(pending_tx['amount_eth'])
            price_change = abs((current_eth - original_eth) / original_eth * 100)
            if price_change > config.slippage_tolerance:
                pending_transactions.pop(tx_id)
                logger.warning(f"Price changed by {price_change:.2f}% for tx: {tx_id}")
                return jsonify({"error": f"Price changed by {price_change:.2f}%. Please retry."}), 400
        
        sender = pending_tx['sender']
        recipient = pending_tx['recipient']
        amount_eth = Decimal(pending_tx['amount_eth'])
        amount_wei = eth_to_wei(amount_eth)
        
        sender_wallet = get_wallet(sender)
        recipient_wallet = get_wallet(recipient)
        
        new_sender_balance = int(sender_wallet['balance_wei']) - amount_wei
        update_wallet_balance(sender, new_sender_balance)
        
        if recipient_wallet:
            new_recipient_balance = int(recipient_wallet['balance_wei']) + amount_wei
            update_wallet_balance(recipient, new_recipient_balance)
        else:
            create_wallet_in_db(recipient, "", "", Decimal(0), None)
            update_wallet_balance(recipient, amount_wei)
        
        save_transaction(sender, recipient, amount_wei, pending_tx['message'])
        pending_transactions.pop(tx_id)
        
        # Notifications
        if sender_wallet.get('notification_email'):
            send_notification(
                sender_wallet['notification_email'],
                "Transfer Sent",
                f"You sent {amount_eth} ETH to {recipient}",
                NotificationType.EMAIL
            )
        if recipient_wallet and recipient_wallet.get('notification_email'):
            send_notification(
                recipient_wallet['notification_email'],
                "Transfer Received",
                f"You received {amount_eth} ETH from {sender}",
                NotificationType.EMAIL
            )
        send_notification(
            TELEGRAM_CHAT_ID,
            "Transfer Completed",
            f"✅ Transfer Complete\n{amount_eth} ETH sent from {sender[:10]}... to {recipient[:10]}...",
            NotificationType.TELEGRAM
        )
        
        logger.info(f"Executed transfer: {tx_id} from {sender} to {recipient}")
        return jsonify({
            "success": True,
            "message": "Transfer completed successfully",
            "new_balance": str(wei_to_eth(new_sender_balance))
        })
    except Exception as e:
        logger.error(f"Error executing transfer: {str(e)}")
        return jsonify({"error": "Failed to execute transfer"}), 500

@app.route('/api/transactions/<address>', methods=['GET'])
def get_transactions(address: str):
    """Get transaction history for an address."""
    try:
        if not validate_address(address):
            return jsonify({"error": "Invalid address format"}), 400
            
        txs = list_transactions_for_address(address)
        formatted = []
        for tx in txs:
            formatted.append({
                "id": tx['id'],
                "sender": tx['sender'],
                "recipient": tx['recipient'],
                "amount": str(wei_to_eth(int(tx['amount_wei']))),
                "note": tx.get('note', ''),
                "timestamp": tx['timestamp']['_seconds'],
                "type": "sent" if tx['sender'].lower() == address.lower() else "received"
            })
        logger.info(f"Retrieved {len(txs)} transactions for {address}")
        return jsonify({"transactions": formatted})
    except Exception as e:
        logger.error(f"Error retrieving transactions for {address}: {str(e)}")
        return jsonify({"error": "Failed to retrieve transactions"}), 500

@app.route('/api/sign', methods=['POST'])
def sign_message():
    """Sign a message with a private key."""
    try:
        data = request.json or {}
        message = data.get('message')
        private_key = data.get('private_key')
        
        if not message or not private_key:
            logger.warning("Missing message or private key for signing")
            return jsonify({"error": "Message and private key required"}), 400
            
        if not isinstance(message, str) or len(message) > 1000:
            return jsonify({"error": "Invalid message format or length"}), 400
            
        signature = sign_message_with_private_key(message, private_key)
        logger.info("Message signed successfully")
        return jsonify({"signature": signature})
    except Exception as e:
        logger.error(f"Error signing message: {str(e)}")
        return jsonify({"error": "Failed to sign message"}), 500

# ==================== CLEANUP THREAD ====================

def cleanup_expired():
    """Clean up expired pending transactions."""
    while True:
        try:
            time.sleep(10)
            current_time = time.time()
            expired = [k for k, v in pending_transactions.items() if v['expires_at'] < current_time]
            for k in expired:
                del pending_transactions[k]
                logger.info(f"Cleaned up expired transaction: {k}")
        except Exception as e:
            logger.error(f"Error in cleanup thread: {str(e)}")

if __name__ == '__main__':
    threading.Thread(target=cleanup_expired, daemon=True).start()
    app.run(
        host='0.0.0.0',
        port=int(os.getenv("PORT", 5000)),
        debug=os.getenv("FLASK_ENV") == "development"
    )