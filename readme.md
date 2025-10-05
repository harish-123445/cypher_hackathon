# Mock Web3 Wallet API

A Flask-based mock Web3 wallet backend with Ethereum wallet generation, import, transfer functionality, and Firebase Realtime Database integration. Supports email notification.

---

## Features

* Generate new Ethereum wallets with 12-word mnemonic phrases.
* Import existing wallets using mnemonic phrases.
* Query wallet balance and transaction history.
* Prepare and execute ETH or USD-denominated transfers.
* Sign and verify messages with Ethereum private keys.
* Notifications via **Email**.
* Firebase Realtime Database integration for wallet and transaction storage.
* Automatic cleanup of expired pending transactions.

---

## Tech Stack

* **Backend**: Python 3.11+, Flask
* **Blockchain Utilities**: `bip_utils`, `eth_account`
* **Database**: Firebase Realtime Database
* **Notifications**: SMTP Email
* **Dependencies**: Managed via PDM (`pdm.lock`)

---

## Setup

### 1. Clone the repository

```bash
git clone <repository_url>
cd <repository_folder>
```

### 2. Install PDM and dependencies

Make sure you have [PDM](https://pdm.fming.dev/) installed.

```bash
pdm install
```

This will install all packages listed in `pdm.lock`.

### 3. Environment Variables

Create a `.env` file in the root directory with the following:

```dotenv
FIREBASE_CREDENTIALS=./serviceAccount.json
FIREBASE_URL="DB_URI"
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=yourgmail@gmail.com
SMTP_PASSWORD= password
ALLOWED_ORIGINS=http://localhost:3000
PORT=5000
FLASK_ENV=production
```

### 4. Configuration

Edit `config.json`:

```json
{
  "skip_url": "https://api.skip.exchange/quote",
  "pending_tx_expiry": 300,
  "slippage_tolerance": 5,
  "starting_balance_min": 1.0,
  "starting_balance_max": 10.0,
  "eth_chain_id": "1",
  "usdc_contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "wallets_collection": "wallets",
  "transactions_collection": "transactions",
  "max_transfer_amount": 1000.0,
  "min_transfer_amount": 0.0001
}
```

### 5. Firebase Setup

1. Create a Firebase project and generate a service account JSON file.
2. Set `FIREBASE_CREDENTIALS` to the path of your JSON file.
3. Ensure the Realtime Database URL is set in `.env`.

---

## Run the Application

```bash
python app.py
```

The server will run at `http://localhost:5000/`.

---

## API Endpoints

| Endpoint                      | Method | Description                                                               |
| ----------------------------- | ------ | ------------------------------------------------------------------------- |
| `/`                           | GET    | Homepage                                                                  |
| `/api/wallet/generate`        | POST   | Generate new wallet (JSON: `email`)                                       |
| `/api/wallet/import`          | POST   | Import wallet (JSON: `mnemonic`, `account_index`, `email`)                |
| `/api/wallet/<address>`       | GET    | Get wallet info                                                           |
| `/api/transfer/prepare`       | POST   | Prepare a transfer (JSON: `sender`, `recipient`, `amount`, `amount_mode`) |
| `/api/transfer/execute`       | POST   | Execute transfer (JSON: `tx_id`, `signature`)                             |
| `/api/transactions/<address>` | GET    | Get transaction history                                                   |
| `/api/sign`                   | POST   | Sign a message (JSON: `message`, `private_key`)                           |

---

## Utilities

* `utils.py` provides:

  * Wallet CRUD operations on Firebase.
  * Transaction management.
  * ETH/Wei conversions.

---

## Notes

* Pending transactions expire automatically based on `pending_tx_expiry`.
* Email notifications require proper SMTP setup.
