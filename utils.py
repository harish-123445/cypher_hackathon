import firebase_admin
from firebase_admin import credentials, db
import os
import time
from decimal import Decimal
import logging
import json

# Initialize logging
logger = logging.getLogger(__name__)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Initialize Firebase
SERVICE_ACCOUNT_PATH = os.getenv("FIREBASE_CREDENTIALS", "serviceAccount.json")
FIREBASE_URL = os.getenv("FIREBASE_URL", "https://cypherhackathon-default-rtdb.firebaseio.com/")

if not os.path.exists(SERVICE_ACCOUNT_PATH):
    logger.error(f"Firebase credentials not found: {SERVICE_ACCOUNT_PATH}")
    raise FileNotFoundError(f"Firebase credentials not found: {SERVICE_ACCOUNT_PATH}")

cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_URL})

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)
WALLETS_COLLECTION = config['wallets_collection']
TXNS_COLLECTION = config['transactions_collection']

# ==================== HELPERS ====================

def firestore_timestamp():
    """Generate Firebase-compatible timestamp."""
    try:
        return {"_seconds": int(time.time()), "_nanoseconds": 0}
    except Exception as e:
        logger.error(f"Error generating timestamp: {str(e)}")
        raise

def eth_to_wei(eth_amount: Decimal) -> int:
    """Convert ETH to Wei."""
    try:
        return int(eth_amount * Decimal(10)**18)
    except Exception as e:
        logger.error(f"Error converting ETH to Wei: {str(e)}")
        raise

def wei_to_eth(wei: int) -> Decimal:
    """Convert Wei to ETH."""
    try:
        return Decimal(wei) / Decimal(10)**18
    except Exception as e:
        logger.error(f"Error converting Wei to ETH: {str(e)}")
        raise

# ==================== WALLET CRUD ====================

def create_wallet_in_db(address: str, mnemonic: str, pk_hex: str, balance_eth: Decimal, email: str = None):
    """Create a wallet in Firebase."""
    try:
        data = {
            "address": address.lower(),
            "hashed_mnemonic": mnemonic,
            "hashed_private_key": pk_hex,
            "balance_wei": str(eth_to_wei(balance_eth)),
            "created_at": firestore_timestamp(),
            "updated_at": firestore_timestamp(),
        }
        if email:
            data["notification_email"] = email
        ref = db.reference(f"{WALLETS_COLLECTION}/{address.lower()}")
        ref.set(data)
        logger.info(f"Created wallet in DB: {address}")
    except Exception as e:
        logger.error(f"Error creating wallet in DB for {address}: {str(e)}")
        raise

def get_wallet(address: str):
    """Retrieve wallet from Firebase."""
    try:
        ref = db.reference(f"{WALLETS_COLLECTION}/{address.lower()}")
        data = ref.get()
        if data:
            data["balance_wei"] = data.get("balance_wei", "0")
            logger.info(f"Retrieved wallet: {address}")
        return data
    except Exception as e:
        logger.error(f"Error retrieving wallet for {address}: {str(e)}")
        raise

def update_wallet_balance(address: str, new_balance_wei: int):
    """Update wallet balance in Firebase."""
    try:
        update_data = {
            "balance_wei": str(new_balance_wei),
            "updated_at": firestore_timestamp()
        }
        ref = db.reference(f"{WALLETS_COLLECTION}/{address.lower()}")
        ref.update(update_data)
        logger.info(f"Updated balance for {address}")
    except Exception as e:
        logger.error(f"Error updating balance for {address}: {str(e)}")
        raise

# ==================== TRANSACTION CRUD ====================

def save_transaction(sender: str, recipient: str, amount_wei: int, note: str):
    """Save transaction to Firebase."""
    try:
        data = {
            "sender": sender.lower(),
            "recipient": recipient.lower(),
            "amount_wei": str(amount_wei),
            "note": note,
            "timestamp": firestore_timestamp(),
        }
        ref = db.reference(TXNS_COLLECTION)
        ref.push(data)
        logger.info(f"Saved transaction from {sender} to {recipient}")
    except Exception as e:
        logger.error(f"Error saving transaction from {sender} to {recipient}: {str(e)}")
        raise

def list_transactions_for_address(address: str):
    """List transactions for a given address."""
    try:
        addr_lower = address.lower()
        ref = db.reference(TXNS_COLLECTION)
        all_txs = ref.order_by_child("timestamp/_seconds").get()
        txs = []
        if all_txs:
            for k, tx in all_txs.items():
                if isinstance(tx, dict) and (tx.get("sender") == addr_lower or tx.get("recipient") == addr_lower):
                    tx["id"] = k
                    txs.append(tx)
        txs.sort(key=lambda x: x.get("timestamp", {"_seconds": 0})["_seconds"], reverse=True)
        logger.info(f"Retrieved {len(txs)} transactions for {address}")
        return txs
    except Exception as e:
        logger.error(f"Error listing transactions for {address}: {str(e)}")
        raise