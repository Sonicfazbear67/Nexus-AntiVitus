// System time updater
function updateSystemTime() {
    const now = new Date();
    const timeString = now.toUTCString().replace('GMT', 'ZULU');
    document.getElementById('system-time').textContent = timeString;
    document.getElementById('vm-time').textContent = now.toTimeString().split(' ')[0];
}
setInterval(updateSystemTime, 1000);
updateSystemTime();

// Tab functionality
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const tabId = tab.getAttribute('data-tab');
        
        // Deactivate all tabs and contents
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Activate clicked tab and content
        tab.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    });
});

// Link scanner
document.getElementById('scan-link-btn').addEventListener('click', () => {
    const linkInput = document.getElementById('link-input').value.trim();
    const resultsDiv = document.getElementById('link-results');
    
    if (!linkInput) {
        resultsDiv.innerHTML = `
            <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Please enter a valid URL to scan</div>
        `;
        return;
    }
    
    resultsDiv.innerHTML = `
        <div class="result-line"><span class="result-icon info"><i class="fas fa-sync fa-spin"></i></span> Scanning URL: ${linkInput}</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-cog fa-spin"></i></span> Initiating deep scan protocol...</div>
    `;
    
    setTimeout(() => {
        const isSafe = Math.random() > 0.3;
        const isPhishing = Math.random() > 0.7;
        const hasMalware = Math.random() > 0.8;
        
        let resultsHTML = `
            <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> SSL Certificate: Valid (SHA-256 Encryption)</div>
            <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Domain age: ${Math.floor(Math.random() * 10) + 1} years</div>
        `;
        
        if (isSafe) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Threat assessment: LOW RISK</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> No malware detected</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Phishing check: Negative</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-shield-alt"></i></span> This URL appears to be safe to visit</div>
            `;
        } else {
            if (isPhishing) {
                resultsHTML += `
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-times-circle"></i></span> ⚠️ HIGH RISK: Phishing website detected</div>
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-times-circle"></i></span> This site mimics a legitimate service to steal credentials</div>
                `;
            }
            
            if (hasMalware) {
                resultsHTML += `
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-skull-crossbones"></i></span> MALWARE DETECTED: Drive-by download threat</div>
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-times-circle"></i></span> This site hosts malicious JavaScript payload</div>
                `;
            }
            
            resultsHTML += `
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Security recommendation: BLOCK AND REPORT</div>
            `;
        }
        
        resultsDiv.innerHTML = resultsHTML;
    }, 1500);
});

// File scanner
document.getElementById('upload-area').addEventListener('click', () => {
    document.getElementById('file-input').click();
});

document.getElementById('file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    const resultsDiv = document.getElementById('file-results');
    
    if (!file) return;
    
    resultsDiv.innerHTML = `
        <div class="result-line"><span class="result-icon info"><i class="fas fa-sync fa-spin"></i></span> Analyzing file: ${file.name}</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-cog fa-spin"></i></span> File size: ${(file.size / 1024 / 1024).toFixed(2)} MB</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-cog fa-spin"></i></span> Type: ${file.type || 'Unknown'}</div>
    `;
    
    setTimeout(() => {
        const isMalicious = Math.random() > 0.7;
        const fileType = file.name.split('.').pop().toUpperCase();
        
        let resultsHTML = `
            <div class="result-line"><span class="result-icon info"><i class="fas fa-file"></i></span> File: ${file.name}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-hashtag"></i></span> SHA-256 Hash: ${generateRandomHash()}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-microchip"></i></span> Static analysis complete</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-brain"></i></span> Behavioral analysis complete</div>
        `;
        
        if (isMalicious) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-virus"></i></span> ⚠️ MALWARE DETECTED: Trojan.${String.fromCharCode(65 + Math.floor(Math.random() * 26))}${Math.floor(Math.random() * 9999)}</div>
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-times-circle"></i></span> Threat level: HIGH - This file contains malicious code</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Action taken: File quarantined for further analysis</div>
            `;
        } else {
            resultsHTML += `
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> No known threats detected</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> File appears to be clean and safe</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> Heuristic analysis: No suspicious behavior</div>
            `;
        }
        
        resultsDiv.innerHTML = resultsHTML;
    }, 2000);
});

// Phone scanner
document.getElementById('scan-phone-btn').addEventListener('click', () => {
    const phoneInput = document.getElementById('phone-input').value.trim();
    const resultsDiv = document.getElementById('phone-results');
    
    if (!phoneInput) {
        resultsDiv.innerHTML = `
            <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Please enter a phone number to scan</div>
        `;
        return;
    }
    
    resultsDiv.innerHTML = `
        <div class="result-line"><span class="result-icon info"><i class="fas fa-sync fa-spin"></i></span> Analyzing phone number: ${phoneInput}</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-cog fa-spin"></i></span> Checking global spam databases...</div>
    `;
    
    setTimeout(() => {
        const isSpam = Math.random() > 0.6;
        const isScam = Math.random() > 0.8;
        const reportCount = Math.floor(Math.random() * 100);
        
        let resultsHTML = `
            <div class="result-line"><span class="result-icon info"><i class="fas fa-phone"></i></span> Phone number: ${phoneInput}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-globe"></i></span> Location: ${generateRandomLocation()}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-database"></i></span> Database checks: ${Math.floor(Math.random() * 5) + 3} of 5 completed</div>
        `;
        
        if (isScam) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-skull-crossbones"></i></span> ⚠️ HIGH RISK: Confirmed scam number</div>
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-times-circle"></i></span> This number is associated with financial fraud</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Reports: ${reportCount + 50} user reports</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Recommendation: BLOCK IMMEDIATELY</div>
            `;
        } else if (isSpam) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> MEDIUM RISK: Likely spam telemarketer</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Reports: ${reportCount} user reports</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> This number may be a telemarketing service</div>
            `;
        } else {
            resultsHTML += `
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> LOW RISK: No significant threats detected</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Minimal user reports: ${reportCount}</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> This number appears to be safe</div>
            `;
        }
        
        resultsDiv.innerHTML = resultsHTML;
    }, 1800);
});

// System scanner
document.getElementById('system-scan-btn').addEventListener('click', () => {
    const progressDiv = document.getElementById('system-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressPercent = document.getElementById('progress-percent');
    const resultsDiv = document.getElementById('system-results');
    
    progressDiv.style.display = 'block';
    resultsDiv.innerHTML = `
        <div class="result-line"><span class="result-icon info"><i class="fas fa-sync fa-spin"></i></span> Initializing system scan...</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-cog fa-spin"></i></span> Loading threat databases...</div>
    `;
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 5;
        if (progress > 100) progress = 100;
        
        progressFill.style.width = `${progress}%`;
        progressPercent.textContent = `${Math.floor(progress)}%`;
        
        if (progress === 100) {
            clearInterval(interval);
            setTimeout(() => {
                displaySystemScanResults();
            }, 500);
        }
    }, 200);
});

function displaySystemScanResults() {
    const resultsDiv = document.getElementById('system-results');
    const threatsFound = Math.floor(Math.random() * 10);
    const vulnerabilities = Math.floor(Math.random() * 5);
    
    let resultsHTML = `
        <div class="result-line"><span class="result-icon info"><i class="fas fa-flag-checkered"></i></span> System scan completed at ${new Date().toLocaleTimeString()}</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-hdd"></i></span> Files scanned: ${Math.floor(Math.random() * 50000) + 30000}</div>
        <div class="result-line"><span class="result-icon info"><i class="fas fa-clock"></i></span> Scan duration: ${Math.floor(Math.random() * 5) + 2} minutes</div>
    `;
    
    if (threatsFound > 0) {
        resultsHTML += `
            <div class="result-line"><span class="result-icon danger"><i class="fas fa-virus"></i></span> THREATS DETECTED: ${threatsFound} malicious items found</div>
            <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> ${vulnerabilities} system vulnerabilities identified</div>
            <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Immediate action recommended</div>
        `;
    } else {
        resultsHTML += `
            <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> No malware or viruses detected</div>
            <div class="result-line"><span class="result-icon safe"><i class="fas fa-shield-alt"></i></span> Your system appears to be clean and secure</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> ${vulnerabilities} non-critical vulnerabilities found</div>
        `;
    }
    
    resultsDiv.innerHTML = resultsHTML;
}

// VM Test Environment
document.getElementById('vm-execute-btn').addEventListener('click', () => {
    const vmInput = document.getElementById('vm-input').value.trim();
    const vmOutput = document.getElementById('vm-output');
    
    if (!vmInput) {
        addVMOutputLine(`<span class="vm-prompt">vm-user@nexus:~$</span> <span class="vm-command">ERROR: No input provided for VM test</span>`);
        return;
    }
    
    addVMOutputLine(`<span class="vm-prompt">vm-user@nexus:~$</span> <span class="vm-command">execute --vm-test "${vmInput}"</span>`);
    
    setTimeout(() => {
        if (vmInput.startsWith('http')) {
            addVMOutputLine(`Opening URL in isolated browser: ${vmInput}`);
            addVMOutputLine(`VM Network: Redirecting to sandboxed environment...`);
            addVMOutputLine(`Page loaded successfully. Analyzing content...`);
            
            if (Math.random() > 0.5) {
                addVMOutputLine(`<span style="color:var(--safe)">Result: No malicious activity detected. Page appears safe.</span>`);
            } else {
                addVMOutputLine(`<span style="color:var(--danger)">WARNING: Suspicious JavaScript detected! Possible drive-by download attempt.</span>`);
                addVMOutputLine(`<span style="color:var(--warning)">VM Action: Blocked connection to malicious IP: 192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}</span>`);
            }
        } else {
            addVMOutputLine(`Executing file in sandbox: ${vmInput}`);
            addVMOutputLine(`VM File System: File loaded into memory (${Math.floor(Math.random() * 50) + 10}MB)`);
            addVMOutputLine(`Behavior monitor: Tracking file execution...`);
            
            if (Math.random() > 0.6) {
                addVMOutputLine(`<span style="color:var(--safe)">Result: File executed normally. No suspicious system modifications.</span>`);
            } else {
                addVMOutputLine(`<span style="color:var(--danger)">ALERT: File attempted to modify registry keys!</span>`);
                addVMOutputLine(`<span style="color:var(--danger)">File attempted to establish outbound connection to command server.</span>`);
                addVMOutputLine(`<span style="color:var(--warning)">VM Action: Process terminated. File quarantined for analysis.</span>`);
            }
        }
        
        addVMOutputLine(`<span class="vm-prompt">vm-user@nexus:~$</span> <span class="vm-command" id="current-command">_</span>`);
    }, 1000);
});

function addVMOutputLine(line) {
    const vmOutput = document.getElementById('vm-output');
    const newLine = document.createElement('div');
    newLine.className = 'vm-line';
    newLine.innerHTML = line;
    vmOutput.appendChild(newLine);
    vmOutput.scrollTop = vmOutput.scrollHeight;
}

// Helper functions
function generateRandomHash() {
    const chars = '0123456789abcdef';
    let hash = '';
    for (let i = 0; i < 64; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
    }
    return hash;
}

function generateRandomLocation() {
    const locations = ['United States', 'Canada', 'United Kingdom', 'Germany', 'Australia', 'India', 'Singapore', 'Brazil', 'Nigeria', 'Unknown'];
    return locations[Math.floor(Math.random() * locations.length)];
}

// Blinking cursor effect for VM
setInterval(() => {
    const cursor = document.getElementById('current-command');
    if (cursor) {
        cursor.textContent = cursor.textContent === '_' ? '' : '_';
    }
}, 500);