// PlayNexus JWT Decoder & Validator - Main Process
// Owner: Nortaq | Contact: playnexushq@gmail.com

const { app, BrowserWindow, ipcMain, Menu, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const { jwtVerify, SignJWT } = require('jose');
const Store = require('electron-store');
const { autoUpdater } = require('electron-updater');

// Security modules
const SecurityUtils = require('../shared/security-utils');
const ErrorHandler = require('../shared/error-handler');
const SecurityHardening = require('../shared/security-hardening');
const axios = require('axios');
const { format, isAfter, isBefore, addDays } = require('date-fns');

// Initialize secure store
const store = new Store({
    encryptionKey: 'playnexus-jwt-decoder-validator-key',
    name: 'jwt-decoder-settings'
});

let mainWindow;
let isDev = process.argv.includes('--dev');

// Initialize error handler
const errorHandler = new ErrorHandler('PlayNexus JWT Decoder & Validator');

// Apply security hardening
SecurityHardening.applyElectronSecurity();

// Security: Prevent new window creation
app.on('web-contents-created', (event, contents) => {
    contents.on('new-window', (event, navigationUrl) => {
        event.preventDefault();
        shell.openExternal(navigationUrl);
    });
});

function createWindow() {
    mainWindow = SecurityHardening.createSecureWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js')
        },
        icon: path.join(__dirname, '../assets/icon.png'),
        title: 'PlayNexus JWT Decoder & Validator',
        show: false,
        titleBarStyle: 'default'
    });

    mainWindow.loadFile(path.join(__dirname, 'renderer/index.html'));

    // Show window when ready
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        if (isDev) {
            mainWindow.webContents.openDevTools();
        }
    });

    // Handle window closed
    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    // Create application menu
    createMenu();

    // Setup auto-updater
    if (!isDev) {
        autoUpdater.checkForUpdatesAndNotify();
    }
}

function createMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'New JWT Analysis',
                    accelerator: 'CmdOrCtrl+N',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'new-analysis');
                    }
                },
                { type: 'separator' },
                {
                    label: 'Import JWT from File',
                    accelerator: 'CmdOrCtrl+O',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'import-jwt');
                    }
                },
                {
                    label: 'Export Results',
                    submenu: [
                        {
                            label: 'Export as JSON',
                            click: () => {
                                mainWindow.webContents.send('menu-action', 'export-json');
                            }
                        },
                        {
                            label: 'Export as CSV',
                            click: () => {
                                mainWindow.webContents.send('menu-action', 'export-csv');
                            }
                        },
                        {
                            label: 'Export as PDF',
                            click: () => {
                                mainWindow.webContents.send('menu-action', 'export-pdf');
                            }
                        }
                    ]
                },
                { type: 'separator' },
                {
                    label: 'Exit',
                    accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
                    click: () => {
                        app.quit();
                    }
                }
            ]
        },
        {
            label: 'Tools',
            submenu: [
                {
                    label: 'Generate JWT',
                    accelerator: 'CmdOrCtrl+G',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'generate-jwt');
                    }
                },
                {
                    label: 'Validate Signature',
                    accelerator: 'CmdOrCtrl+V',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'validate-signature');
                    }
                },
                { type: 'separator' },
                {
                    label: 'Settings',
                    accelerator: 'CmdOrCtrl+,',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'settings');
                    }
                }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'Help & Documentation',
                    accelerator: 'F1',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'help');
                    }
                },
                {
                    label: 'JWT Standards (RFC 7519)',
                    click: () => {
                        shell.openExternal('https://tools.ietf.org/html/rfc7519');
                    }
                },
                { type: 'separator' },
                {
                    label: 'About',
                    click: () => {
                        mainWindow.webContents.send('menu-action', 'about');
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

// JWT Analysis Functions
async function analyzeJWT(jwtToken, options = {}) {
    try {
        const analysis = {
            token: jwtToken,
            timestamp: new Date().toISOString(),
            valid: false,
            header: null,
            payload: null,
            signature: null,
            algorithm: null,
            keyId: null,
            issuer: null,
            subject: null,
            audience: null,
            expiresAt: null,
            issuedAt: null,
            notBefore: null,
            jwtId: null,
            claims: {},
            security: {
                score: 0,
                issues: [],
                recommendations: [],
                vulnerabilities: []
            },
            validation: {
                structure: false,
                signature: false,
                expiration: false,
                timing: false,
                claims: false
            }
        };

        // Step 1: Decode JWT structure
        const decodedStructure = await decodeJWTStructure(jwtToken);
        analysis.header = decodedStructure.header;
        analysis.payload = decodedStructure.payload;
        analysis.signature = decodedStructure.signature;
        analysis.validation.structure = decodedStructure.valid;

        if (!analysis.validation.structure) {
            analysis.security.issues.push('Invalid JWT structure - token is malformed');
            return analysis;
        }

        // Step 2: Extract standard claims
        extractStandardClaims(analysis);

        // Step 3: Validate timing claims
        validateTimingClaims(analysis);

        // Step 4: Security analysis
        await performSecurityAnalysis(analysis, options);

        // Step 5: Signature validation (if secret/key provided)
        if (options.secret || options.publicKey) {
            await validateSignature(analysis, options);
        }

        // Step 6: Calculate overall security score
        calculateSecurityScore(analysis);

        analysis.valid = analysis.validation.structure && 
                        analysis.validation.expiration && 
                        analysis.validation.timing;

        return analysis;

    } catch (error) {
        throw new Error(`JWT analysis failed: ${error.message}`);
    }
}

async function decodeJWTStructure(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, error: 'Invalid JWT structure - must have 3 parts' };
        }

        // Decode header
        const headerBuffer = Buffer.from(parts[0], 'base64url');
        const header = JSON.parse(headerBuffer.toString());

        // Decode payload
        const payloadBuffer = Buffer.from(parts[1], 'base64url');
        const payload = JSON.parse(payloadBuffer.toString());

        // Extract signature (keep as base64url)
        const signature = parts[2];

        return {
            valid: true,
            header,
            payload,
            signature,
            parts
        };

    } catch (error) {
        return { valid: false, error: error.message };
    }
}

function extractStandardClaims(analysis) {
    const payload = analysis.payload;
    
    analysis.algorithm = analysis.header.alg;
    analysis.keyId = analysis.header.kid;
    analysis.issuer = payload.iss;
    analysis.subject = payload.sub;
    analysis.audience = payload.aud;
    analysis.expiresAt = payload.exp ? new Date(payload.exp * 1000) : null;
    analysis.issuedAt = payload.iat ? new Date(payload.iat * 1000) : null;
    analysis.notBefore = payload.nbf ? new Date(payload.nbf * 1000) : null;
    analysis.jwtId = payload.jti;

    // Extract all claims
    analysis.claims = { ...payload };
}

function validateTimingClaims(analysis) {
    const now = new Date();
    let timingValid = true;

    // Check expiration
    if (analysis.expiresAt) {
        if (isAfter(now, analysis.expiresAt)) {
            analysis.security.issues.push(`Token expired on ${format(analysis.expiresAt, 'PPpp')}`);
            analysis.validation.expiration = false;
            timingValid = false;
        } else {
            analysis.validation.expiration = true;
            
            // Check if expiring soon
            const daysTillExpiry = Math.ceil((analysis.expiresAt - now) / (1000 * 60 * 60 * 24));
            if (daysTillExpiry <= 7) {
                analysis.security.recommendations.push(`Token expires in ${daysTillExpiry} days - consider renewal`);
            }
        }
    } else {
        analysis.security.recommendations.push('Token has no expiration time - consider adding exp claim');
    }

    // Check not before
    if (analysis.notBefore) {
        if (isBefore(now, analysis.notBefore)) {
            analysis.security.issues.push(`Token not valid until ${format(analysis.notBefore, 'PPpp')}`);
            timingValid = false;
        }
    }

    // Check issued at
    if (analysis.issuedAt) {
        if (isAfter(analysis.issuedAt, now)) {
            analysis.security.issues.push('Token issued in the future - possible clock skew');
            timingValid = false;
        }
    }

    analysis.validation.timing = timingValid;
}

async function performSecurityAnalysis(analysis, options) {
    const algorithm = analysis.algorithm;
    const header = analysis.header;
    const payload = analysis.payload;

    // Algorithm security analysis
    analyzeAlgorithm(analysis, algorithm);

    // Header security analysis
    analyzeHeader(analysis, header);

    // Payload security analysis
    analyzePayload(analysis, payload);

    // Check for common vulnerabilities
    checkCommonVulnerabilities(analysis);

    // Validate required claims
    validateRequiredClaims(analysis, options.requiredClaims || []);
}

function analyzeAlgorithm(analysis, algorithm) {
    const secureAlgorithms = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
    const weakAlgorithms = ['HS256', 'HS384', 'HS512'];
    const insecureAlgorithms = ['none', 'RS1', 'ES1'];

    if (insecureAlgorithms.includes(algorithm)) {
        analysis.security.issues.push(`Insecure algorithm: ${algorithm}`);
        analysis.security.vulnerabilities.push({
            name: 'Insecure Algorithm',
            severity: 'High',
            description: `Algorithm ${algorithm} is considered insecure and should not be used`,
            recommendation: 'Use RS256, ES256, or other secure algorithms'
        });
    } else if (weakAlgorithms.includes(algorithm)) {
        analysis.security.recommendations.push(`Consider upgrading from ${algorithm} to RS256 or ES256 for better security`);
    } else if (secureAlgorithms.includes(algorithm)) {
        // Good algorithm
    } else {
        analysis.security.issues.push(`Unknown or unsupported algorithm: ${algorithm}`);
    }
}

function analyzeHeader(analysis, header) {
    // Check for critical header parameters
    if (header.crit) {
        analysis.security.recommendations.push('Token uses critical header parameters - ensure proper validation');
    }

    // Check for key ID
    if (!header.kid && ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'].includes(header.alg)) {
        analysis.security.recommendations.push('Consider adding kid (Key ID) header for key management');
    }

    // Check for type
    if (header.typ && header.typ.toLowerCase() !== 'jwt') {
        analysis.security.recommendations.push(`Unusual token type: ${header.typ}`);
    }
}

function analyzePayload(analysis, payload) {
    const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
    const missingClaims = requiredClaims.filter(claim => !payload[claim]);

    if (missingClaims.length > 0) {
        analysis.security.recommendations.push(`Consider adding standard claims: ${missingClaims.join(', ')}`);
    }

    // Check for sensitive data in payload
    const sensitiveKeys = ['password', 'secret', 'key', 'token', 'ssn', 'credit_card'];
    const foundSensitive = Object.keys(payload).filter(key => 
        sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))
    );

    if (foundSensitive.length > 0) {
        analysis.security.issues.push(`Potentially sensitive data in payload: ${foundSensitive.join(', ')}`);
    }

    // Check payload size
    const payloadSize = JSON.stringify(payload).length;
    if (payloadSize > 8192) {
        analysis.security.recommendations.push('Large payload detected - consider reducing token size for better performance');
    }
}

function checkCommonVulnerabilities(analysis) {
    // Check for algorithm confusion attack
    if (analysis.algorithm === 'none') {
        analysis.security.vulnerabilities.push({
            name: 'Algorithm Confusion (None Algorithm)',
            severity: 'Critical',
            description: 'Token uses "none" algorithm which bypasses signature verification',
            recommendation: 'Never accept tokens with "none" algorithm in production'
        });
    }

    // Check for weak HMAC keys (if we had access to the key)
    if (['HS256', 'HS384', 'HS512'].includes(analysis.algorithm)) {
        analysis.security.recommendations.push('Ensure HMAC secret is at least 256 bits and cryptographically random');
    }

    // Check for missing audience validation
    if (!analysis.audience) {
        analysis.security.recommendations.push('Add audience (aud) claim to prevent token misuse across services');
    }

    // Check for overly broad scope
    if (analysis.payload.scope && typeof analysis.payload.scope === 'string') {
        const scopes = analysis.payload.scope.split(' ');
        if (scopes.includes('*') || scopes.includes('admin') || scopes.includes('root')) {
            analysis.security.recommendations.push('Review token scopes - avoid overly broad permissions');
        }
    }
}

function validateRequiredClaims(analysis, requiredClaims) {
    const missingRequired = requiredClaims.filter(claim => !analysis.payload[claim]);
    
    if (missingRequired.length > 0) {
        analysis.security.issues.push(`Missing required claims: ${missingRequired.join(', ')}`);
        analysis.validation.claims = false;
    } else {
        analysis.validation.claims = true;
    }
}

async function validateSignature(analysis, options) {
    try {
        const { secret, publicKey, algorithm } = options;
        
        if (secret && ['HS256', 'HS384', 'HS512'].includes(analysis.algorithm)) {
            // HMAC validation
            const verified = jwt.verify(analysis.token, secret, { algorithms: [analysis.algorithm] });
            analysis.validation.signature = true;
        } else if (publicKey && ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'].includes(analysis.algorithm)) {
            // RSA/ECDSA validation
            const verified = jwt.verify(analysis.token, publicKey, { algorithms: [analysis.algorithm] });
            analysis.validation.signature = true;
        }
    } catch (error) {
        analysis.validation.signature = false;
        analysis.security.issues.push(`Signature validation failed: ${error.message}`);
    }
}

function calculateSecurityScore(analysis) {
    let score = 100;
    
    // Deduct points for issues
    score -= analysis.security.issues.length * 15;
    
    // Deduct points for vulnerabilities
    analysis.security.vulnerabilities.forEach(vuln => {
        switch (vuln.severity.toLowerCase()) {
            case 'critical': score -= 30; break;
            case 'high': score -= 20; break;
            case 'medium': score -= 10; break;
            case 'low': score -= 5; break;
        }
    });
    
    // Deduct points for missing validations
    if (!analysis.validation.structure) score -= 25;
    if (!analysis.validation.expiration) score -= 20;
    if (!analysis.validation.timing) score -= 15;
    if (!analysis.validation.signature) score -= 10;
    
    // Bonus points for good practices
    if (analysis.expiresAt) score += 5;
    if (analysis.audience) score += 5;
    if (analysis.keyId) score += 5;
    
    analysis.security.score = Math.max(0, Math.min(100, score));
}

async function generateJWT(payload, options = {}) {
    try {
        const {
            algorithm = 'HS256',
            secret,
            privateKey,
            expiresIn = '1h',
            issuer,
            audience,
            subject,
            keyId
        } = options;

        const signOptions = {
            algorithm,
            expiresIn,
            issuer,
            audience,
            subject,
            keyId
        };

        // Remove undefined options
        Object.keys(signOptions).forEach(key => {
            if (signOptions[key] === undefined) {
                delete signOptions[key];
            }
        });

        let token;
        if (['HS256', 'HS384', 'HS512'].includes(algorithm)) {
            if (!secret) throw new Error('Secret required for HMAC algorithms');
            token = jwt.sign(payload, secret, signOptions);
        } else if (['RS256', 'RS384', 'RS512'].includes(algorithm)) {
            if (!privateKey) throw new Error('Private key required for RSA algorithms');
            token = jwt.sign(payload, privateKey, signOptions);
        } else {
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        }

        return {
            token,
            header: jwt.decode(token, { complete: true }).header,
            payload: jwt.decode(token, { complete: true }).payload
        };

    } catch (error) {
        throw new Error(`JWT generation failed: ${error.message}`);
    }
}

// IPC Handlers with security validation
ipcMain.handle('analyze-jwt', errorHandler.createSafeIpcHandler(async (event, data) => {
    const { token, options } = data;
    
    // Validate JWT input
    const validatedToken = SecurityUtils.validateInput(token, 'jwt');
    
    return await errorHandler.safeAsync(
        () => analyzeJWT(validatedToken, options),
        'JWT Analysis',
        { timeout: 10000, retries: 1 }
    );
}, 'analyze-jwt'));

ipcMain.handle('generate-jwt', errorHandler.createSafeIpcHandler(async (event, data) => {
    const { payload, options } = data;
    
    // Validate payload
    if (typeof payload !== 'object' || payload === null) {
        throw new Error('Payload must be a valid object');
    }
    
    return await errorHandler.safeAsync(
        () => generateJWT(payload, options),
        'JWT Generation',
        { timeout: 5000, retries: 1 }
    );
}, 'generate-jwt'));

ipcMain.handle('validate-signature', errorHandler.createSafeIpcHandler(async (event, data) => {
    const { token, secret, publicKey } = data;
    
    // Validate JWT input
    const validatedToken = SecurityUtils.validateInput(token, 'jwt');
    
    const analysis = { token: validatedToken, validation: {} };
    
    return await errorHandler.safeAsync(
        () => validateSignature(analysis, { secret, publicKey }),
        'Signature Validation',
        { timeout: 5000, retries: 1 }
    );
}, 'validate-signature'));

ipcMain.handle('import-jwt-file', errorHandler.createSafeIpcHandler(async (event) => {
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Import JWT from File',
        filters: [
            { name: 'Text Files', extensions: ['txt', 'jwt', 'token'] },
            { name: 'All Files', extensions: ['*'] }
        ],
        properties: ['openFile']
    });

    if (result.canceled) {
        return { success: false, message: 'Import canceled' };
    }

    const filePath = result.filePaths[0];
    
    // Validate file access
    SecurityUtils.validateFileAccess(filePath, [app.getPath('documents'), app.getPath('downloads')]);
    
    const content = await fs.readFile(filePath, 'utf8');
    
    // Validate content size
    if (content.length > 10000) {
        throw new Error('File too large (max 10KB)');
    }
    
    return {
        success: true,
        message: `Results exported successfully`,
        filePath: sanitizedPath
    };
}, 'export-results'));

ipcMain.handle('get-settings', errorHandler.createSafeIpcHandler(async (event) => {
    return store.get('settings', {
        theme: 'dark',
        autoValidate: true,
        showSensitiveData: false,
        saveHistory: true,
        requiredClaims: ['iss', 'exp'],
        defaultAlgorithm: 'HS256',
        tokenExpiry: '1h'
    });
}, 'get-settings'));

ipcMain.handle('save-settings', errorHandler.createSafeIpcHandler(async (event, settings) => {
    // Validate settings object
    if (typeof settings !== 'object' || settings === null) {
        throw new Error('Settings must be a valid object');
    }
    
    // Sanitize settings
    const sanitizedSettings = {
        theme: ['dark', 'light'].includes(settings.theme) ? settings.theme : 'dark',
        autoValidate: Boolean(settings.autoValidate),
        showSensitiveData: Boolean(settings.showSensitiveData),
        saveHistory: Boolean(settings.saveHistory),
        requiredClaims: Array.isArray(settings.requiredClaims) ? settings.requiredClaims.slice(0, 10) : ['iss', 'exp'],
        defaultAlgorithm: typeof settings.defaultAlgorithm === 'string' ? settings.defaultAlgorithm.substring(0, 20) : 'HS256',
        tokenExpiry: typeof settings.tokenExpiry === 'string' ? settings.tokenExpiry.substring(0, 10) : '1h'
    };
    
    store.set('settings', sanitizedSettings);
    return true;
}, 'save-settings'));

ipcMain.handle('save-to-history', errorHandler.createSafeIpcHandler(async (event, data) => {
    // Validate history data
    if (typeof data !== 'object' || data === null) {
        throw new Error('History data must be a valid object');
    }
    
    const history = store.get('history', []);
    
    // Sanitize history entry
    const sanitizedEntry = {
        timestamp: new Date().toISOString(),
        token: typeof data.token === 'string' ? data.token.substring(0, 100) + '...' : '',
        analysis: data.analysis ? {
            algorithm: data.analysis.algorithm,
            issuer: data.analysis.issuer,
            subject: data.analysis.subject,
            expiresAt: data.analysis.expiresAt
        } : null
    };
    
    history.unshift(sanitizedEntry);
    
    // Keep only last 100 entries
    if (history.length > 100) {
        history.splice(100);
    }
    
    store.set('history', history);
    return true;
}, 'save-to-history'));

ipcMain.handle('get-history', errorHandler.createSafeIpcHandler(async (event) => {
    return store.get('history', []);
}, 'get-history'));

// Utility functions
function convertToCSV(results) {
    const headers = ['Field', 'Value'];
    const rows = [
        ['Token Valid', results.valid],
        ['Algorithm', results.algorithm],
        ['Issuer', results.issuer || 'N/A'],
        ['Subject', results.subject || 'N/A'],
        ['Audience', results.audience || 'N/A'],
        ['Expires At', results.expiresAt || 'N/A'],
        ['Issued At', results.issuedAt || 'N/A'],
        ['Security Score', results.security.score],
        ['Issues Count', results.security.issues.length],
        ['Vulnerabilities Count', results.security.vulnerabilities.length]
    ];
    
    return [headers, ...rows].map(row => row.map(field => `"${field}"`).join(',')).join('\n');
}

function formatForPDF(results) {
    return `JWT Analysis Report
Generated: ${new Date().toISOString()}

Token Information:
- Valid: ${results.valid}
- Algorithm: ${results.algorithm}
- Issuer: ${results.issuer || 'N/A'}
- Subject: ${results.subject || 'N/A'}
- Audience: ${results.audience || 'N/A'}
- Expires At: ${results.expiresAt || 'N/A'}
- Issued At: ${results.issuedAt || 'N/A'}

Security Analysis:
- Score: ${results.security.score}/100
- Issues: ${results.security.issues.length}
- Vulnerabilities: ${results.security.vulnerabilities.length}

Issues:
${results.security.issues.map(issue => `- ${issue}`).join('\n')}

Vulnerabilities:
${results.security.vulnerabilities.map(vuln => `- ${vuln.name} (${vuln.severity}): ${vuln.description}`).join('\n')}

Recommendations:
${results.security.recommendations.map(rec => `- ${rec}`).join('\n')}
`;
}

// App event handlers
app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// Auto-updater events
autoUpdater.on('checking-for-update', () => {
    console.log('Checking for update...');
});

autoUpdater.on('update-available', (info) => {
    console.log('Update available.');
});

autoUpdater.on('update-not-available', (info) => {
    console.log('Update not available.');
});

autoUpdater.on('error', (err) => {
    console.log('Error in auto-updater. ' + err);
});

autoUpdater.on('download-progress', (progressObj) => {
    let log_message = "Download speed: " + progressObj.bytesPerSecond;
    log_message = log_message + ' - Downloaded ' + progressObj.percent + '%';
    log_message = log_message + ' (' + progressObj.transferred + "/" + progressObj.total + ')';
    console.log(log_message);
});

autoUpdater.on('update-downloaded', (info) => {
    console.log('Update downloaded');
    autoUpdater.quitAndInstall();
});
