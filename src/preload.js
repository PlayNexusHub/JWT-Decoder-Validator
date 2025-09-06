// PlayNexus JWT Decoder & Validator - Preload Script
// Owner: Nortaq | Contact: playnexushq@gmail.com

const { contextBridge, ipcRenderer } = require('electron');

// Expose secure API to renderer process
contextBridge.exposeInMainWorld('electronAPI', {
    // JWT Analysis
    analyzeJWT: (data) => ipcRenderer.invoke('analyze-jwt', data),
    generateJWT: (data) => ipcRenderer.invoke('generate-jwt', data),
    validateSignature: (data) => ipcRenderer.invoke('validate-signature', data),
    
    // File operations
    importJWTFile: () => ipcRenderer.invoke('import-jwt-file'),
    exportResults: (data) => ipcRenderer.invoke('export-results', data),
    
    // Settings
    getSettings: () => ipcRenderer.invoke('get-settings'),
    saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
    
    // History
    saveToHistory: (data) => ipcRenderer.invoke('save-to-history', data),
    getHistory: () => ipcRenderer.invoke('get-history'),
    
    // Menu events
    onMenuAction: (callback) => {
        ipcRenderer.on('menu-action', (event, action) => callback(action));
    }
});
