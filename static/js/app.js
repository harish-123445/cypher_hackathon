// Global state
let currentWallet = null;
let currentPrivateKey = null;
let pendingTx = null;
let transactionChart = null;

// Screen Management
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

// Toast Notifications
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 4000);
}

// Loading Overlay
function showLoading(show = true) {
    const overlay = document.getElementById('loadingOverlay');
    if (show) {
        overlay.classList.add('active');
    } else {
        overlay.classList.remove('active');
    }
}

// Update Wallet Status
function updateWalletStatus(connected) {
    const status = document.getElementById('walletStatus');
    if (connected) {
        status.classList.add('connected');
        status.querySelector('span:last-child').textContent = 'Connected';
    } else {
        status.classList.remove('connected');
        status.querySelector('span:last-child').textContent = 'Not Connected';
    }
}

// Create Wallet Form Handler
document.getElementById('createForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    showLoading(true);
    
    const email = document.getElementById('createEmail').value;
    
    try {
        const response = await fetch('/api/wallet/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Display mnemonic
        displayMnemonic(data.mnemonic);
        currentWallet = data.address;
        currentPrivateKey = data.private_key;
        
        showToast('Wallet created successfully!', 'success');
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        showLoading(false);
    }
});

// Display Mnemonic
function displayMnemonic(mnemonic) {
    const words = mnemonic.split(' ');
    const grid = document.getElementById('mnemonicGrid');
    grid.innerHTML = '';
    
    words.forEach((word, index) => {
        const wordEl = document.createElement('div');
        wordEl.className = 'mnemonic-word';
        wordEl.innerHTML = `<span>${index + 1}</span>${word}`;
        grid.appendChild(wordEl);
    });
    
    document.getElementById('mnemonicDisplay').style.display = 'block';
    document.getElementById('createForm').style.display = 'none';
}

// Confirm Mnemonic and Load Wallet
async function confirmMnemonic() {
    await loadWallet(currentWallet);
    showScreen('dashboardScreen');
}

// Import Wallet Form Handler
document.getElementById('importForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    showLoading(true);
    
    const mnemonic = document.getElementById('importMnemonic').value.trim();
    const accountIndex = parseInt(document.getElementById('accountIndex').value);
    const email = document.getElementById('importEmail').value;
    
    try {
        const response = await fetch('/api/wallet/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mnemonic, account_index: accountIndex, email })
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        currentWallet = data.address;
        currentPrivateKey = data.private_key;
        
        showToast(data.existing ? 'Wallet imported!' : 'Wallet created and imported!', 'success');
        await loadWallet(currentWallet);
        showScreen('dashboardScreen');
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        showLoading(false);
    }
});

// Load Wallet Data
async function loadWallet(address) {
    try {
        const response = await fetch(`/api/wallet/${address}`);
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        document.getElementById('walletAddress').textContent = address;
        document.getElementById('balanceAmount').textContent = parseFloat(data.balance).toFixed(4);
        document.getElementById('sendBalanceDisplay').textContent = `${parseFloat(data.balance).toFixed(4)} ETH`;
        
        updateWalletStatus(true);
        
        // Load transactions for chart
        await loadTransactionChart();
    } catch (error) {
        showToast(error.message, 'error');
    }
}

// Copy Address
function copyAddress() {
    const address = document.getElementById('walletAddress').textContent;
    navigator.clipboard.writeText(address);
    showToast('Address copied to clipboard!', 'success');
}

// Send Form Handler
document.getElementById('sendForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    showLoading(true);
    
    const recipient = document.getElementById('recipientAddress').value.trim();
    const amount = document.getElementById('amount').value;
    const amountMode = document.querySelector('input[name="amountMode"]:checked').value;
    
    try {
        const response = await fetch('/api/transfer/prepare', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender: currentWallet,
                recipient,
                amount,
                amount_mode: amountMode
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Show approval modal
        pendingTx = data;
        document.getElementById('approvalMessage').textContent = data.message;
        document.getElementById('approvalAmount').textContent = `${data.eth_amount} ETH`;
        document.getElementById('approvalModal').classList.add('active');
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        showLoading(false);
    }
});

// Approve and Execute Transaction
async function approveTransaction() {
    if (!pendingTx || !currentPrivateKey) {
        showToast('No pending transaction', 'error');
        return;
    }
    
    showLoading(true);
    closeApprovalModal();
    
    try {
        // Sign the message
        const signResponse = await fetch('/api/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: pendingTx.message,
                private_key: currentPrivateKey
            })
        });
        
        const signData = await signResponse.json();
        
        if (signData.error) {
            throw new Error(signData.error);
        }
        
        // Execute transfer
        const execResponse = await fetch('/api/transfer/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tx_id: pendingTx.tx_id,
                signature: signData.signature
            })
        });
        
        const execData = await execResponse.json();
        
        if (execData.error) {
            throw new Error(execData.error);
        }
        
        showToast('Transfer completed successfully!', 'success');
        
        // Reset form
        document.getElementById('sendForm').reset();
        
        // Reload wallet data
        await loadWallet(currentWallet);
        
        // Show dashboard
        showScreen('dashboardScreen');
        
        pendingTx = null;
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// Close Approval Modal
function closeApprovalModal() {
    document.getElementById('approvalModal').classList.remove('active');
}

// Load Transactions
async function loadTransactions() {
    if (!currentWallet) {
        showToast('No wallet loaded', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch(`/api/transactions/${currentWallet}`);
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        const list = document.getElementById('transactionList');
        list.innerHTML = '';
        
        if (data.transactions.length === 0) {
            list.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">No transactions yet</p>';
        } else {
            data.transactions.forEach(tx => {
                const item = document.createElement('div');
                item.className = 'transaction-item';
                
                const type = tx.type === 'sent' ? 'Sent' : 'Received';
                const typeClass = tx.type;
                const icon = tx.type === 'sent' ? 'fa-arrow-up' : 'fa-arrow-down';
                const otherAddress = tx.type === 'sent' ? tx.recipient : tx.sender;
                const date = new Date(tx.timestamp * 1000);
                
                item.innerHTML = `
                    <div class="transaction-info">
                        <div class="transaction-type ${typeClass}">
                            <i class="fas ${icon}"></i>
                            ${type}
                        </div>
                        <div class="transaction-address">${otherAddress}</div>
                    </div>
                    <div class="transaction-amount">
                        <strong>${tx.type === 'sent' ? '-' : '+'}${parseFloat(tx.amount).toFixed(4)} ETH</strong>
                        <div class="transaction-time">${date.toLocaleString()}</div>
                    </div>
                `;
                
                list.appendChild(item);
            });
        }
        
        showScreen('historyScreen');
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// Load Transaction Chart
async function loadTransactionChart() {
    if (!currentWallet) return;
    
    try {
        const response = await fetch(`/api/transactions/${currentWallet}`);
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        const sent = data.transactions.filter(tx => tx.type === 'sent').length;
        const received = data.transactions.filter(tx => tx.type === 'received').length;
        
        const ctx = document.getElementById('transactionChart');
        
        if (transactionChart) {
            transactionChart.destroy();
        }
        
        if (sent === 0 && received === 0) {
            ctx.getContext('2d').fillStyle = '#cbd5e1';
            ctx.getContext('2d').font = '14px Inter';
            ctx.getContext('2d').textAlign = 'center';
            ctx.getContext('2d').fillText('No transactions yet', ctx.width / 2, ctx.height / 2);
            return;
        }
        
        transactionChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Sent', 'Received'],
                datasets: [{
                    data: [sent, received],
                    backgroundColor: ['#ef4444', '#10b981'],
                    borderColor: '#1e293b',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f8fafc',
                            font: {
                                family: 'Inter'
                            }
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Chart error:', error);
    }
}

// Disconnect Wallet
function disconnectWallet() {
    if (confirm('Are you sure you want to disconnect your wallet?')) {
        currentWallet = null;
        currentPrivateKey = null;
        pendingTx = null;
        
        updateWalletStatus(false);
        showScreen('welcomeScreen');
        showToast('Wallet disconnected', 'success');
    }
}

// Check storage mode and show warning
async function checkStorageMode() {
    try {
        const response = await fetch('/api/wallet/0x0000000000000000000000000000000000000000');
        const isMemoryMode = response.status === 404;
        if (isMemoryMode) {
            document.getElementById('storageWarning').style.display = 'flex';
        }
    } catch (error) {
        document.getElementById('storageWarning').style.display = 'flex';
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('Mock Web3 Wallet initialized');
    checkStorageMode();
});
