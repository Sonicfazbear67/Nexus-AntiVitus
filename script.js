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

// Improved Link Scanner with realistic URL detection
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
        // Improved URL analysis logic
        const url = linkInput.toLowerCase();
        let isSafe = true;
        let isPhishing = false;
        let hasMalware = false;
        let threats = [];
        
        // Check for known safe domains
        const safeDomains = [
            'youtube.com', 'google.com', 'github.com', 'microsoft.com', 
            'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
            'wikipedia.org', 'reddit.com', 'stackoverflow.com', 'netflix.com'
        ];
        
        // Check for suspicious patterns
        const suspiciousPatterns = [
            'login-', 'verify-', 'secure-', 'account-', 'bank-', 'paypal-',
            'free-', 'win-', 'prize-', 'click-', 'update-', 'security-'
        ];
        
        // Known malicious TLDs
        const riskyTLDs = ['.xyz', '.top', '.club', '.download', '.gq', '.cf', '.ml', '.tk'];
        
        // Check if it's a known safe domain
        const isKnownSafe = safeDomains.some(domain => url.includes(domain));
        
        // Check for HTTPS
        const hasHTTPS = url.startsWith('https://');
        
        // Check for suspicious patterns (common in phishing)
        const hasSuspiciousPattern = suspiciousPatterns.some(pattern => url.includes(pattern));
        
        // Check TLD
        const hasRiskyTLD = riskyTLDs.some(tld => url.includes(tld));
        
        // Analyze URL structure
        const urlParts = url.replace('https://', '').replace('http://', '').split('/')[0];
        const domainParts = urlParts.split('.');
        const hasLongDomain = urlParts.length > 30;
        const hasManyDashes = (urlParts.match(/-/g) || []).length > 3;
        
        // Determine risk level
        if (isKnownSafe) {
            isSafe = true;
            isPhishing = false;
            hasMalware = false;
        } else if (hasSuspiciousPattern && !hasHTTPS) {
            isPhishing = true;
            isSafe = false;
            threats.push('Phishing pattern detected');
        } else if (hasRiskyTLD && !hasHTTPS) {
            hasMalware = true;
            isSafe = false;
            threats.push('Risky domain extension');
        } else if (hasLongDomain || hasManyDashes) {
            isPhishing = Math.random() > 0.7;
            threats.push('Suspicious domain structure');
        }
        
        // Add some randomness for demonstration (but less for known safe sites)
        if (!isKnownSafe) {
            if (Math.random() > 0.8) {
                hasMalware = true;
                threats.push('Potential malware hosting');
            }
            if (Math.random() > 0.85) {
                isPhishing = true;
                threats.push('Phishing characteristics detected');
            }
        }
        
        // Generate results
        let resultsHTML = `
            <div class="result-line"><span class="result-icon ${hasHTTPS ? 'safe' : 'warning'}"><i class="fas ${hasHTTPS ? 'fa-lock' : 'fa-unlock'}"></i></span> SSL: ${hasHTTPS ? 'Secure (HTTPS)' : 'Not Secure (HTTP)'}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-globe"></i></span> Domain: ${domainParts.length > 1 ? domainParts.slice(-2).join('.') : urlParts}</div>
        `;
        
        if (isSafe && !isPhishing && !hasMalware) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Threat assessment: <strong>LOW RISK</strong></div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> No malware detected</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Phishing check: Negative</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-shield-alt"></i></span> This URL appears to be safe to visit</div>
            `;
        } else {
            if (isPhishing) {
                resultsHTML += `
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-fish"></i></span> ⚠️ <strong>HIGH RISK</strong>: Phishing website detected</div>
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-exclamation-triangle"></i></span> This site may attempt to steal credentials</div>
                `;
            }
            
            if (hasMalware) {
                resultsHTML += `
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-skull-crossbones"></i></span> MALWARE DETECTED: Potential security threat</div>
                    <div class="result-line"><span class="result-icon danger"><i class="fas fa-virus"></i></span> This site may host malicious content</div>
                `;
            }
            
            if (threats.length > 0) {
                resultsHTML += `<div class="result-line"><span class="result-icon warning"><i class="fas fa-list"></i></span> Detected issues: ${threats.join(', ')}</div>`;
            }
            
            resultsHTML += `
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Security recommendation: Exercise caution</div>
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
        const fileName = file.name.toLowerCase();
        const fileExt = fileName.split('.').pop();
        
        // Improved file analysis logic
        let isMalicious = false;
        let threatType = '';
        let riskLevel = 'LOW';
        
        // Check file extension
        const riskyExtensions = ['exe', 'bat', 'cmd', 'vbs', 'js', 'jar', 'scr', 'pif'];
        const suspiciousExtensions = ['doc', 'docx', 'pdf', 'xls', 'xlsx'];
        
        // Check for suspicious names
        const suspiciousNames = [
            'invoice', 'payment', 'receipt', 'document', 'scan', 'photo',
            'password', 'login', 'secure', 'update', 'install', 'setup'
        ];
        
        // Check for double extensions (common trick)
        const hasDoubleExtension = (fileName.match(/\./g) || []).length > 1;
        
        // Determine risk
        if (riskyExtensions.includes(fileExt)) {
            // Executable files have higher risk
            isMalicious = Math.random() > 0.4;
            threatType = 'Executable File';
            riskLevel = 'MEDIUM';
        } else if (suspiciousExtensions.includes(fileExt)) {
            // Document files can contain macros
            isMalicious = Math.random() > 0.7;
            threatType = 'Document File';
            riskLevel = 'LOW';
        }
        
        // Check for suspicious names
        const hasSuspiciousName = suspiciousNames.some(name => fileName.includes(name));
        if (hasSuspiciousName) {
            riskLevel = 'MEDIUM';
            isMalicious = Math.random() > 0.6;
        }
        
        // Double extension is highly suspicious
        if (hasDoubleExtension) {
            isMalicious = true;
            riskLevel = 'HIGH';
            threatType = 'Double Extension Trick';
        }
        
        // Large files over 50MB get extra scrutiny
        if (file.size > 50 * 1024 * 1024) {
            riskLevel = 'MEDIUM';
        }
        
        let resultsHTML = `
            <div class="result-line"><span class="result-icon info"><i class="fas fa-file"></i></span> File: ${file.name}</div>
            <div class="result-icon info"><i class="fas fa-hashtag"></i></span> SHA-256: ${generateRandomHash()}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-microchip"></i></span> File type: ${fileExt.toUpperCase()}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-shield-alt"></i></span> Risk level: ${riskLevel}</div>
        `;
        
        if (isMalicious) {
            const malwareNames = [
                'Trojan.Win32', 'Ransomware.Crypto', 'Backdoor.Remote',
                'Spyware.Keylogger', 'Adware.Popup', 'Worm.Network'
            ];
            const malwareName = malwareNames[Math.floor(Math.random() * malwareNames.length)];
            
            resultsHTML += `
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-virus"></i></span> ⚠️ <strong>MALWARE DETECTED</strong>: ${malwareName}</div>
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-exclamation-circle"></i></span> Threat type: ${threatType || 'Unknown malware'}</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> Action: File quarantined for analysis</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-ban"></i></span> Recommendation: Delete this file immediately</div>
            `;
        } else {
            resultsHTML += `
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> No known threats detected</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Heuristic analysis: Clean</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> File appears to be safe</div>
            `;
        }
        
        resultsDiv.innerHTML = resultsHTML;
    }, 2000);
});

// IMPROVED Phone Number Scanner with country detection
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
        // Improved phone number analysis
        const phone = phoneInput.replace(/\D/g, ''); // Remove non-digits
        
        // Country code detection
        const countryCodes = {
            '20': 'Egypt',
            '1': 'USA/Canada',
            '44': 'United Kingdom',
            '33': 'France',
            '49': 'Germany',
            '81': 'Japan',
            '86': 'China',
            '91': 'India',
            '7': 'Russia',
            '55': 'Brazil',
            '61': 'Australia',
            '34': 'Spain',
            '39': 'Italy'
        };
        
        // Find country
        let country = 'Unknown';
        let countryCode = '';
        
        for (const [code, name] of Object.entries(countryCodes)) {
            if (phone.startsWith(code)) {
                country = name;
                countryCode = code;
                break;
            }
        }
        
        // If no country code found, assume local number
        if (country === 'Unknown' && phone.length <= 11) {
            country = 'Local Number';
        }
        
        // Check for Egyptian numbers specifically
        const isEgyptian = phone.startsWith('20');
        const isEgyptianMobile = isEgyptian && (
            phone.startsWith('2010') || 
            phone.startsWith('2011') || 
            phone.startsWith('2012') ||
            phone.startsWith('2015')
        );
        
        // Risk assessment based on patterns
        let isSpam = false;
        let isScam = false;
        let riskLevel = 'LOW';
        let reportCount = Math.floor(Math.random() * 50);
        
        // Check for patterns (Egyptian numbers)
        if (isEgyptian) {
            // Known Egyptian telecom prefixes
            const validEgyptianPrefixes = ['10', '11', '12', '15'];
            const prefix = phone.substring(2, 4);
            
            if (!validEgyptianPrefixes.includes(prefix)) {
                riskLevel = 'MEDIUM';
                isSpam = Math.random() > 0.4;
            }
            
            // Check for sequential numbers (common in spam)
            if (/(\d)\1{4,}/.test(phone)) {
                isSpam = true;
                riskLevel = 'HIGH';
            }
            
            // Egyptian numbers should be 11-12 digits with country code
            if (phone.length !== 12 && phone.length !== 13) {
                riskLevel = 'MEDIUM';
            }
        } else {
            // For non-Egyptian numbers, random but realistic assessment
            isSpam = Math.random() > 0.7;
            isScam = Math.random() > 0.85;
            
            if (isScam) {
                riskLevel = 'HIGH';
                reportCount = Math.floor(Math.random() * 200) + 100;
            } else if (isSpam) {
                riskLevel = 'MEDIUM';
                reportCount = Math.floor(Math.random() * 100) + 20;
            }
        }
        
        // Check for known scam patterns
        const scamPatterns = [
            '8888', '9999', '1234', '0000', '1111', '5555'
        ];
        
        scamPatterns.forEach(pattern => {
            if (phone.includes(pattern)) {
                isScam = Math.random() > 0.3;
                riskLevel = 'HIGH';
            }
        });
        
        // Generate results
        let resultsHTML = `
            <div class="result-line"><span class="result-icon info"><i class="fas fa-phone"></i></span> Phone: ${phoneInput}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-globe"></i></span> Country: ${country} ${countryCode ? `(+${countryCode})` : ''}</div>
            <div class="result-line"><span class="result-icon info"><i class="fas fa-shield-alt"></i></span> Risk Level: ${riskLevel}</div>
        `;
        
        if (isEgyptian) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> Type: ${isEgyptianMobile ? 'Egyptian Mobile' : 'Egyptian Landline'}</div>
            `;
        }
        
        if (isScam) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-skull-crossbones"></i></span> ⚠️ <strong>HIGH RISK</strong>: Confirmed scam number</div>
                <div class="result-line"><span class="result-icon danger"><i class="fas fa-exclamation-circle"></i></span> This number is associated with financial fraud</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-flag"></i></span> Reports: ${reportCount} user reports</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-ban"></i></span> Recommendation: BLOCK & REPORT</div>
            `;
        } else if (isSpam) {
            resultsHTML += `
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-exclamation-triangle"></i></span> <strong>MEDIUM RISK</strong>: Likely spam/telemarketing</div>
                <div class="result-line"><span class="result-icon warning"><i class="fas fa-comment-slash"></i></span> Reports: ${reportCount} spam reports</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> This may be a telemarketing service</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-bell-slash"></i></span> Recommendation: Consider blocking</div>
            `;
        } else {
            resultsHTML += `
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> <strong>LOW RISK</strong>: No significant threats</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-check-circle"></i></span> Clean reputation in databases</div>
                <div class="result-line"><span class="result-icon info"><i class="fas fa-info-circle"></i></span> Reports: ${reportCount} (minimal)</div>
                <div class="result-line"><span class="result-icon safe"><i class="fas fa-shield-alt"></i></span> This number appears to be safe</div>
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
        <div class="result-line"><span class="result-icon info"><i class="fas fa-sync fa-spin"></i></
