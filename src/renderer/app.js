// PlayNexus JWT Decoder & Validator - Renderer Process
// Owner: Nortaq | Contact: playnexushq@gmail.com

class JWTAnalyzer {
    constructor() {
        this.currentResults = null;
        this.settings = {
            theme: 'dark',
            autoValidate: true,
            showSensitiveData: false,
            saveHistory: true,
            requiredClaims: ['iss', 'exp'],
            defaultAlgorithm: 'HS256',
            tokenExpiry: '1h'
        };
        this.exampleTokens = {
            valid: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.Lkylp7BK3X3-HuFqYNzWlUNTnQNyJVjJgCzLhfTFLyU',
            expired: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            invalid: 'invalid.jwt.token'
        };
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.setupTabs();
        await this.loadSettings();
        this.applyTheme();
        
        // Handle menu events
        window.electronAPI.onMenuAction((action) => {
            this.handleMenuAction(action);
        });
    }

    setupEventListeners() {
        // Main analysis
        document.getElementById('analyzeBtn').addEventListener('click', () => this.analyzeJWT());
        document.getElementById('clearBtn').addEventListener('click', () => this.clearResults());
        
        // JWT input auto-analysis
        const jwtInput = document.getElementById('jwtToken');
        jwtInput.addEventListener('input', () => {
            if (this.settings.autoValidate && jwtInput.value.trim()) {
                this.debounce(() => this.analyzeJWT(), 1000)();
            }
        });

        // Example tokens
        document.querySelectorAll('.example-token').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const type = e.target.dataset.type;
                document.getElementById('jwtToken').value = this.exampleTokens[type];
                this.analyzeJWT();
            });
        });

        // Validation options
        document.getElementById('validateSignature').addEventListener('change', (e) => {
            document.getElementById('secretSection').style.display = e.target.checked ? 'block' : 'none';
        });

        // Toggle secret visibility
        document.getElementById('toggleSecret').addEventListener('click', () => {
            const input = document.getElementById('secretKey');
            const type = input.type === 'password' ? 'text' : 'password';
            input.type = type;
            document.getElementById('toggleSecret').textContent = type === 'password' ? '👁️' : '🙈';
        });

        // Header actions
        document.getElementById('importBtn').addEventListener('click', () => this.importJWT());
        document.getElementById('generateBtn').addEventListener('click', () => this.showModal('generateModal'));
        document.getElementById('settingsBtn').addEventListener('click', () => this.showModal('settingsModal'));
        document.getElementById('helpBtn').addEventListener('click', () => this.showModal('helpModal'));

        // Export buttons
        document.getElementById('exportJson').addEventListener('click', () => this.exportResults('json'));
        document.getElementById('exportCsv').addEventListener('click', () => this.exportResults('csv'));
        document.getElementById('exportPdf').addEventListener('click', () => this.exportResults('pdf'));

        // Copy buttons
        document.getElementById('copyHeader').addEventListener('click', () => this.copyToClipboard('headerJson'));
        document.getElementById('copyPayload').addEventListener('click', () => this.copyToClipboard('payloadJson'));

        // Signature validation
        document.getElementById('validateBtn').addEventListener('click', () => this.validateSignature());

        // Generate JWT
        document.getElementById('generateToken').addEventListener('click', () => this.generateJWT());
        document.getElementById('copyGenerated').addEventListener('click', () => this.copyToClipboard('generatedToken'));

        // Modal controls
        this.setupModalControls();
    }

    setupTabs() {
        const tabs = document.querySelectorAll('.analysis-tab');
        const panes = document.querySelectorAll('.tab-pane');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetPane = tab.dataset.tab;
                
                // Update active tab
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                // Update active pane
                panes.forEach(p => p.classList.remove('active'));
                document.getElementById(targetPane).classList.add('active');
            });
        });
    }

    setupModalControls() {
        // Settings modal
        document.getElementById('saveSettings').addEventListener('click', () => {
            this.saveSettings();
        });

        // Close modals
        document.querySelectorAll('.modal-close, .btn-secondary').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const modal = e.target.closest('.modal');
                if (modal) this.hideModal(modal.id);
            });
        });

        // Click outside to close
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.hideModal(modal.id);
            });
        });
    }

    async analyzeJWT() {
        const token = document.getElementById('jwtToken').value.trim();
        
        if (!token) {
            this.showError('Please enter a JWT token');
            return;
        }

        const validateSignature = document.getElementById('validateSignature').checked;
        const secret = document.getElementById('secretKey').value.trim();

        this.showLoading();
        
        try {
            const options = {
                requiredClaims: this.settings.requiredClaims
            };

            if (validateSignature && secret) {
                if (secret.startsWith('-----BEGIN')) {
                    options.publicKey = secret;
                } else {
                    options.secret = secret;
                }
            }

            const results = await window.electronAPI.analyzeJWT({
                token,
                options
            });
            
            this.currentResults = results;
            this.displayResults(results);
            
            if (this.settings.saveHistory) {
                await this.saveToHistory(token, results);
            }
            
        } catch (error) {
            this.showError(`Analysis failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    displayResults(results) {
        this.hideNoResults();
        this.showResults();
        
        // Update score
        this.updateScore(results.security.score);
        
        // Update validation status
        this.updateValidationStatus(results.validation);
        
        // Update overview
        this.updateOverview(results);
        
        // Update header tab
        this.updateHeader(results.header);
        
        // Update payload tab
        this.updatePayload(results.payload);
        
        // Update signature tab
        this.updateSignature(results);
        
        // Update security tab
        this.updateSecurity(results.security);
        
        // Update claims tab
        this.updateClaims(results.claims);
        
        // Show export section
        document.querySelector('.export-section').style.display = 'block';
    }

    updateScore(score) {
        const scoreValue = document.querySelector('.score-value');
        const scoreGrade = document.querySelector('.score-grade');
        const scoreFill = document.querySelector('.score-fill');
        const scoreCircle = document.querySelector('.score-circle');
        
        scoreValue.textContent = score;
        scoreFill.style.width = `${score}%`;
        
        // Calculate grade
        let grade = 'F';
        if (score >= 90) grade = 'A';
        else if (score >= 80) grade = 'B';
        else if (score >= 70) grade = 'C';
        else if (score >= 60) grade = 'D';
        
        scoreGrade.textContent = grade;
        
        // Update circle gradient
        const degrees = (score / 100) * 360;
        scoreCircle.style.background = `conic-gradient(var(--primary-color) ${degrees}deg, var(--border-color) ${degrees}deg)`;
        
        // Update color based on score
        let color = 'var(--danger-color)';
        if (score >= 80) color = 'var(--success-color)';
        else if (score >= 60) color = 'var(--warning-color)';
        
        scoreValue.style.color = color;
        scoreFill.style.background = color;
    }

    updateValidationStatus(validation) {
        document.getElementById('structureStatus').textContent = validation.structure ? '✅' : '❌';
        document.getElementById('signatureStatus').textContent = validation.signature ? '✅' : '❌';
        document.getElementById('timingStatus').textContent = validation.timing ? '✅' : '❌';
    }

    updateOverview(results) {
        document.getElementById('algorithm').textContent = results.algorithm || '-';
        document.getElementById('issuer').textContent = results.issuer || '-';
        document.getElementById('subject').textContent = results.subject || '-';
        document.getElementById('expiresAt').textContent = results.expiresAt ? this.formatDate(results.expiresAt) : '-';
        document.getElementById('issuedAt').textContent = results.issuedAt ? this.formatDate(results.issuedAt) : '-';
        
        // Token status
        const statusEl = document.getElementById('tokenStatus');
        if (results.valid) {
            statusEl.textContent = 'Valid';
            statusEl.className = 'token-status valid';
        } else if (results.expiresAt && new Date() > new Date(results.expiresAt)) {
            statusEl.textContent = 'Expired';
            statusEl.className = 'token-status expired';
        } else {
            statusEl.textContent = 'Invalid';
            statusEl.className = 'token-status invalid';
        }
        
        // Summary
        document.getElementById('tokenSummary').textContent = this.generateSummary(results);
        
        // Issues
        this.updateIssuesList(results.security.issues);
        
        // Recommendations
        this.updateRecommendationsList(results.security.recommendations);
    }

    updateIssuesList(issues) {
        const issuesList = document.getElementById('issuesList');
        issuesList.innerHTML = '';
        
        if (issues.length === 0) {
            issuesList.innerHTML = '<div class="issue-item" style="background: rgba(40, 167, 69, 0.1); border-color: var(--success-color); color: var(--success-color);">No issues detected</div>';
            return;
        }
        
        issues.forEach(issue => {
            const issueItem = document.createElement('div');
            issueItem.className = 'issue-item';
            issueItem.textContent = issue;
            issuesList.appendChild(issueItem);
        });
    }

    updateRecommendationsList(recommendations) {
        const recList = document.getElementById('recommendationsList');
        recList.innerHTML = '';
        
        if (recommendations.length === 0) {
            recList.innerHTML = '<div class="recommendation-item">No specific recommendations at this time.</div>';
            return;
        }
        
        recommendations.forEach(rec => {
            const recItem = document.createElement('div');
            recItem.className = 'recommendation-item';
            recItem.textContent = rec;
            recList.appendChild(recItem);
        });
    }

    updateHeader(header) {
        document.getElementById('headerJson').textContent = JSON.stringify(header, null, 2);
        document.getElementById('headerAlg').textContent = header.alg || '-';
        document.getElementById('headerTyp').textContent = header.typ || '-';
        document.getElementById('headerKid').textContent = header.kid || '-';
        document.getElementById('headerCty').textContent = header.cty || '-';
    }

    updatePayload(payload) {
        document.getElementById('payloadJson').textContent = JSON.stringify(payload, null, 2);
        
        // Standard claims
        document.getElementById('claimIss').textContent = payload.iss || '-';
        document.getElementById('claimSub').textContent = payload.sub || '-';
        document.getElementById('claimAud').textContent = payload.aud || '-';
        document.getElementById('claimExp').textContent = payload.exp ? this.formatDate(new Date(payload.exp * 1000)) : '-';
        document.getElementById('claimNbf').textContent = payload.nbf ? this.formatDate(new Date(payload.nbf * 1000)) : '-';
        document.getElementById('claimIat').textContent = payload.iat ? this.formatDate(new Date(payload.iat * 1000)) : '-';
        document.getElementById('claimJti').textContent = payload.jti || '-';
    }

    updateSignature(results) {
        document.getElementById('sigAlgorithm').textContent = results.algorithm || '-';
        document.getElementById('signatureValue').textContent = results.signature || '-';
        
        const validationEl = document.getElementById('sigValidation');
        if (results.validation.signature === true) {
            validationEl.textContent = 'Valid';
            validationEl.className = 'validation-badge valid';
        } else if (results.validation.signature === false) {
            validationEl.textContent = 'Invalid';
            validationEl.className = 'validation-badge invalid';
        } else {
            validationEl.textContent = 'Not Validated';
            validationEl.className = 'validation-badge pending';
        }
    }

    updateSecurity(security) {
        // Vulnerabilities
        const vulnList = document.getElementById('vulnerabilitiesList');
        vulnList.innerHTML = '';
        
        if (security.vulnerabilities.length === 0) {
            vulnList.innerHTML = `
                <div class="vulnerability-item" style="background: rgba(40, 167, 69, 0.1); border-color: var(--success-color);">
                    <div class="vulnerability-header">
                        <div class="vulnerability-title" style="color: var(--success-color);">No Known Vulnerabilities</div>
                        <div class="vulnerability-severity" style="background: var(--success-color); color: white;">Good</div>
                    </div>
                    <div>No known JWT vulnerabilities were detected for this token.</div>
                </div>
            `;
        } else {
            security.vulnerabilities.forEach(vuln => {
                const vulnItem = document.createElement('div');
                vulnItem.className = 'vulnerability-item';
                vulnItem.innerHTML = `
                    <div class="vulnerability-header">
                        <div class="vulnerability-title">${vuln.name}</div>
                        <div class="vulnerability-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
                    </div>
                    <div class="vulnerability-description">${vuln.description}</div>
                    ${vuln.recommendation ? `<div class="vulnerability-recommendation"><strong>Recommendation:</strong> ${vuln.recommendation}</div>` : ''}
                `;
                vulnList.appendChild(vulnItem);
            });
        }
        
        // Security checklist
        this.updateSecurityChecklist(security);
    }

    updateSecurityChecklist(security) {
        // This would be based on the analysis results
        const algorithm = this.currentResults.algorithm;
        const secureAlgorithms = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
        
        document.getElementById('checkAlgorithm').textContent = secureAlgorithms.includes(algorithm) ? '✅' : '❌';
        document.getElementById('checkExpiration').textContent = this.currentResults.expiresAt ? '✅' : '❌';
        document.getElementById('checkIssuer').textContent = this.currentResults.issuer ? '✅' : '❌';
        document.getElementById('checkAudience').textContent = this.currentResults.audience ? '✅' : '❌';
        document.getElementById('checkSignature').textContent = this.currentResults.validation.signature ? '✅' : '❌';
    }

    updateClaims(claims) {
        const tableBody = document.getElementById('claimsTableBody');
        tableBody.innerHTML = '';
        
        Object.entries(claims).forEach(([key, value]) => {
            const row = document.createElement('div');
            row.className = 'table-row';
            
            const type = typeof value;
            let displayValue = value;
            
            if (type === 'object') {
                displayValue = JSON.stringify(value);
            } else if (type === 'number' && (key === 'exp' || key === 'iat' || key === 'nbf')) {
                displayValue = `${value} (${this.formatDate(new Date(value * 1000))})`;
            }
            
            row.innerHTML = `
                <div class="table-cell">${key}</div>
                <div class="table-cell">${displayValue}</div>
                <div class="table-cell">${type}</div>
            `;
            
            tableBody.appendChild(row);
        });
    }

    async validateSignature() {
        const secret = document.getElementById('validationSecret').value.trim();
        
        if (!secret) {
            this.showError('Please enter a secret or public key');
            return;
        }
        
        if (!this.currentResults) {
            this.showError('Please analyze a JWT token first');
            return;
        }
        
        try {
            const isValid = await window.electronAPI.validateSignature({
                token: this.currentResults.token,
                secret: secret.startsWith('-----BEGIN') ? null : secret,
                publicKey: secret.startsWith('-----BEGIN') ? secret : null
            });
            
            const validationEl = document.getElementById('sigValidation');
            if (isValid) {
                validationEl.textContent = 'Valid';
                validationEl.className = 'validation-badge valid';
                this.showSuccess('Signature is valid');
            } else {
                validationEl.textContent = 'Invalid';
                validationEl.className = 'validation-badge invalid';
                this.showError('Signature is invalid');
            }
            
        } catch (error) {
            this.showError(`Validation failed: ${error.message}`);
        }
    }

    async generateJWT() {
        try {
            const payload = {};
            
            // Standard claims
            const issuer = document.getElementById('genIssuer').value.trim();
            const subject = document.getElementById('genSubject').value.trim();
            const audience = document.getElementById('genAudience').value.trim();
            
            if (issuer) payload.iss = issuer;
            if (subject) payload.sub = subject;
            if (audience) payload.aud = audience;
            
            // Custom payload
            const customPayload = document.getElementById('genPayload').value.trim();
            if (customPayload) {
                try {
                    const custom = JSON.parse(customPayload);
                    Object.assign(payload, custom);
                } catch (error) {
                    this.showError('Invalid JSON in custom payload');
                    return;
                }
            }
            
            const options = {
                algorithm: document.getElementById('genAlgorithm').value,
                expiresIn: document.getElementById('genExpiry').value,
                secret: document.getElementById('genSecret').value.trim(),
                keyId: document.getElementById('genKeyId').value.trim()
            };
            
            if (!options.secret) {
                this.showError('Please enter a secret or private key');
                return;
            }
            
            const result = await window.electronAPI.generateJWT({
                payload,
                options
            });
            
            document.getElementById('generatedToken').value = result.token;
            this.showSuccess('JWT token generated successfully');
            
        } catch (error) {
            this.showError(`Generation failed: ${error.message}`);
        }
    }

    async importJWT() {
        try {
            const result = await window.electronAPI.importJWTFile();
            
            if (result.success) {
                document.getElementById('jwtToken').value = result.content;
                this.analyzeJWT();
                this.showSuccess('JWT imported successfully');
            }
        } catch (error) {
            this.showError(`Import failed: ${error.message}`);
        }
    }

    async exportResults(format) {
        if (!this.currentResults) {
            this.showError('No results to export');
            return;
        }
        
        try {
            const success = await window.electronAPI.exportResults({
                results: this.currentResults,
                format: format
            });
            
            if (success) {
                this.showSuccess(`Results exported successfully as ${format.toUpperCase()}`);
            }
        } catch (error) {
            this.showError(`Export failed: ${error.message}`);
        }
    }

    async copyToClipboard(elementId) {
        try {
            const element = document.getElementById(elementId);
            const text = element.textContent || element.value;
            await navigator.clipboard.writeText(text);
            this.showSuccess('Copied to clipboard');
        } catch (error) {
            this.showError('Failed to copy to clipboard');
        }
    }

    async loadSettings() {
        try {
            const settings = await window.electronAPI.getSettings();
            this.settings = { ...this.settings, ...settings };
            this.applySettingsToUI();
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    async saveSettings() {
        try {
            // Get values from form
            this.settings.theme = document.getElementById('themeSelect').value;
            this.settings.autoValidate = document.getElementById('autoValidateCheck').checked;
            this.settings.showSensitiveData = document.getElementById('showSensitiveCheck').checked;
            this.settings.saveHistory = document.getElementById('saveHistoryCheck').checked;
            this.settings.requiredClaims = document.getElementById('requiredClaimsInput').value.split(',').map(s => s.trim()).filter(s => s);
            this.settings.defaultAlgorithm = document.getElementById('defaultAlgorithmSelect').value;
            this.settings.tokenExpiry = document.getElementById('tokenExpiryInput').value;
            
            await window.electronAPI.saveSettings(this.settings);
            this.applyTheme();
            this.hideModal('settingsModal');
            this.showSuccess('Settings saved successfully');
        } catch (error) {
            this.showError(`Failed to save settings: ${error.message}`);
        }
    }

    applySettingsToUI() {
        document.getElementById('themeSelect').value = this.settings.theme;
        document.getElementById('autoValidateCheck').checked = this.settings.autoValidate;
        document.getElementById('showSensitiveCheck').checked = this.settings.showSensitiveData;
        document.getElementById('saveHistoryCheck').checked = this.settings.saveHistory;
        document.getElementById('requiredClaimsInput').value = this.settings.requiredClaims.join(', ');
        document.getElementById('defaultAlgorithmSelect').value = this.settings.defaultAlgorithm;
        document.getElementById('tokenExpiryInput').value = this.settings.tokenExpiry;
    }

    applyTheme() {
        document.body.setAttribute('data-theme', this.settings.theme);
    }

    async saveToHistory(token, results) {
        try {
            await window.electronAPI.saveToHistory({
                token: token.substring(0, 50) + '...', // Truncate for privacy
                results,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Failed to save to history:', error);
        }
    }

    handleMenuAction(action) {
        switch (action) {
            case 'new-analysis':
                this.clearResults();
                document.getElementById('jwtToken').focus();
                break;
            case 'import-jwt':
                this.importJWT();
                break;
            case 'export-json':
                this.exportResults('json');
                break;
            case 'export-csv':
                this.exportResults('csv');
                break;
            case 'export-pdf':
                this.exportResults('pdf');
                break;
            case 'generate-jwt':
                this.showModal('generateModal');
                break;
            case 'validate-signature':
                this.validateSignature();
                break;
            case 'settings':
                this.showModal('settingsModal');
                break;
            case 'help':
                this.showModal('helpModal');
                break;
        }
    }

    clearResults() {
        this.currentResults = null;
        this.showNoResults();
        this.hideResults();
        document.getElementById('jwtToken').value = '';
        document.querySelector('.export-section').style.display = 'none';
    }

    generateSummary(results) {
        const parts = [];
        
        if (results.valid) {
            parts.push('Token is structurally valid');
        } else {
            parts.push('Token has validation issues');
        }
        
        if (results.expiresAt) {
            const now = new Date();
            const exp = new Date(results.expiresAt);
            if (exp > now) {
                const days = Math.ceil((exp - now) / (1000 * 60 * 60 * 24));
                parts.push(`expires in ${days} days`);
            } else {
                parts.push('token has expired');
            }
        }
        
        if (results.security.score >= 80) {
            parts.push('security score is good');
        } else if (results.security.score >= 60) {
            parts.push('security score needs improvement');
        } else {
            parts.push('security score is poor');
        }
        
        return parts.join(', ') + '.';
    }

    showLoading() {
        document.querySelector('.loading-state').classList.remove('hidden');
        document.querySelector('.results-section .results-content').classList.add('hidden');
        document.getElementById('analyzeBtn').disabled = true;
    }

    hideLoading() {
        document.querySelector('.loading-state').classList.add('hidden');
        document.getElementById('analyzeBtn').disabled = false;
    }

    showResults() {
        document.querySelector('.results-section .results-content').classList.remove('hidden');
    }

    hideResults() {
        document.querySelector('.results-section .results-content').classList.add('hidden');
    }

    showNoResults() {
        document.querySelector('.no-results').classList.remove('hidden');
    }

    hideNoResults() {
        document.querySelector('.no-results').classList.add('hidden');
    }

    showModal(modalId) {
        document.getElementById(modalId).classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    hideModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
        document.body.style.overflow = 'auto';
    }

    showError(message) {
        // Simple alert for now - could be replaced with toast notifications
        alert(`Error: ${message}`);
    }

    showSuccess(message) {
        // Simple alert for now - could be replaced with toast notifications
        alert(`Success: ${message}`);
    }

    formatDate(date) {
        if (!date) return 'Unknown';
        try {
            return new Date(date).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (error) {
            return date.toString();
        }
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new JWTAnalyzer();
});
