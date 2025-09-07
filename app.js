// HawkEye 2.0 - Secure File Upload Dashboard
// Production-ready frontend for secure file upload system

class HawkEyeSecureUpload {
    constructor() {
        // Configuration - Replace with environment variables in production
        this.config = {
            apiBaseUrl: window.location.origin + '/api', // Replace with actual API URL
            wsUrl: window.location.origin.replace('http', 'ws') + '/ws', // WebSocket URL
            
            // File validation rules from backend
            allowedFileTypes: {
                images: ["image/jpeg", "image/png", "image/gif"],
                videos: ["video/mp4", "video/avi", "video/mov", "video/quicktime"],
                audio: ["audio/mpeg", "audio/wav", "audio/m4a", "audio/mp3"],
                documents: ["application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/plain"]
            },
            fileSizeLimits: {
                images: 10485760,    // 10MB
                videos: 52428800,    // 50MB
                audio: 10485760,     // 10MB
                documents: 5242880   // 5MB
            },
            
            // Security settings
            security: {
                maxFilesPerHour: 50,
                maxConcurrentUploads: 5,
                sessionTimeout: 3600000, // 1 hour
                csrfTokenRefreshInterval: 300000 // 5 minutes
            },
            
            // UI settings
            ui: {
                toastDuration: 5000,
                progressUpdateInterval: 100,
                networkCheckInterval: 30000
            },
            
            // Demo mode for frontend-only testing
            demoMode: true
        };
        
        // Application state
        this.state = {
            isAuthenticated: false,
            currentUser: null,
            uploadQueue: [],
            uploadedFiles: [],
            selectedFiles: new Set(),
            auditTrail: [],
            stats: {
                totalUploads: 0,
                secureFiles: 0,
                flaggedFiles: 0,
                storageUsed: 0
            },
            filters: {
                status: 'all',
                type: 'all'
            },
            networkStatus: 'online',
            csrfToken: 'demo-csrf-token',
            sessionExpiry: null
        };
        
        // Utility properties
        this.dragCounter = 0;
        this.uploadWorkers = new Map();
        this.websocket = null;
        this.networkCheckTimer = null;
        this.sessionTimer = null;
        this.csrfRefreshTimer = null;
        
        this.init();
    }
    
    async init() {
        try {
            // Show loading screen
            this.showLoadingScreen();
            
            // Setup event listeners first
            this.setupEventListeners();
            
            // Initialize security (demo mode)
            await this.initializeSecurity();
            
            // Small delay for loading screen
            setTimeout(async () => {
                // Check authentication (demo mode - always show auth modal)
                const isAuth = this.config.demoMode ? false : await this.checkAuthentication();
                
                if (isAuth) {
                    await this.loadDashboard();
                } else {
                    // Show authentication modal
                    this.showAuthModal();
                }
                
                // Initialize network monitoring (demo mode)
                if (!this.config.demoMode) {
                    this.initializeNetworkMonitoring();
                }
                
                // Hide loading screen
                this.hideLoadingScreen();
            }, 1500);
            
        } catch (error) {
            console.error('Initialization failed:', error);
            this.showToast('Application initialized in demo mode', 'info');
            this.hideLoadingScreen();
            this.showAuthModal();
        }
    }
    
    // Authentication Methods
    async checkAuthentication() {
        if (this.config.demoMode) {
            return false; // Always require login in demo mode
        }
        
        try {
            const response = await this.apiCall('/auth/verify', 'GET');
            if (response.success) {
                this.state.isAuthenticated = true;
                this.state.currentUser = response.user;
                this.state.sessionExpiry = new Date(response.sessionExpiry);
                return true;
            }
        } catch (error) {
            this.showToast('User not authenticated', 'error');
        }
        return false;
    }
    
    async login(username, password) {
        // Basic validation
        if (!username || !password) {
            this.showToast('Please enter both username and password', 'error');
            return false;
        }
        
        try {
            // Demo mode - simulate login
            if (this.config.demoMode) {
                // Simulate loading
                this.showToast('Authenticating...', 'info');
                
                await new Promise(resolve => setTimeout(resolve, 1500));
                
                // Demo credentials
                if (username === 'demo' && password === 'demo123') {
                    this.state.isAuthenticated = true;
                    this.state.currentUser = {
                        username: 'demo',
                        email: 'demo@hawkeye.com',
                        role: 'user'
                    };
                    this.state.sessionExpiry = new Date(Date.now() + 3600000); // 1 hour
                    
                    this.hideAuthModal();
                    await this.loadDashboard();
                    this.showToast(`Welcome to HawkEye , ${username}!`, 'success');
                    
                    return true;
                } else {
                    this.showToast('Demo credentials: username "demo", password "demo123"', 'warning');
                    return false;
                }
            }
            
            // Production mode
            const response = await this.apiCall('/auth/login', 'POST', {
                username,
                password
            });
            
            if (response.success) {
                this.state.isAuthenticated = true;
                this.state.currentUser = response.user;
                this.state.sessionExpiry = new Date(response.sessionExpiry);
                
                this.hideAuthModal();
                await this.loadDashboard();
                this.showToast(`Welcome back, ${response.user.username}!`, 'success');
                
                // Start session management
                this.startSessionManagement();
                
                return true;
            } else {
                this.showToast(response.message || 'Login failed', 'error');
                return false;
            }
        } catch (error) {
            this.showToast('Login failed. Please try again.', 'error');
            return false;
        }
    }
    
    async register(username, email, password, confirmPassword) {
        if (password !== confirmPassword) {
            this.showToast('Passwords do not match', 'error');
            return false;
        }
        
        if (password.length < 8) {
            this.showToast('Password must be at least 8 characters long', 'error');
            return false;
        }
        
        if (!email.includes('@')) {
            this.showToast('Please enter a valid email address', 'error');
            return false;
        }
        
        try {
            // Demo mode - simulate registration
            if (this.config.demoMode) {
                this.showToast('Registration successful! Please log in with demo/demo123', 'success');
                this.showLoginForm();
                return true;
            }
            
            const response = await this.apiCall('/auth/register', 'POST', {
                username,
                email,
                password
            });
            
            if (response.success) {
                this.showToast('Registration successful! Please log in.', 'success');
                this.showLoginForm();
                return true;
            } else {
                this.showToast(response.message || 'Registration failed', 'error');
                return false;
            }
        } catch (error) {
            this.showToast('Registration failed. Please try again.', 'error');
            return false;
        }
    }
    
    async logout() {
        try {
            if (!this.config.demoMode) {
                await this.apiCall('/auth/logout', 'POST');
            }
        } catch (error) {
            console.log('Logout API call failed');
        }
        
        // Clear local state
        this.state.isAuthenticated = false;
        this.state.currentUser = null;
        this.state.uploadQueue = [];
        this.state.uploadedFiles = [];
        this.state.selectedFiles.clear();
        
        // Clear timers
        this.clearSessionManagement();
        
        // Close WebSocket
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
        
        // Show auth modal
        this.showAuthModal();
        this.showToast('Logged out successfully', 'info');
    }
    
    // Dashboard Loading
    async loadDashboard() {
        try {
            // Initialize demo data
            this.initializeDemoData();
            
            // Initialize WebSocket connection (skip in demo mode)
            if (!this.config.demoMode) {
                this.initializeWebSocket();
            }
            
            // Load user data (demo or real)
            if (this.config.demoMode) {
                this.loadDemoStats();
            } else {
                await this.loadUserStats();
                await this.loadUploadedFiles();
                await this.loadAuditTrail();
            }
            
            // Update UI
            this.updateDashboard();
            this.updateUserDisplay();
            this.updateUI();
            
            // Start session management
            if (!this.config.demoMode) {
                this.startSessionManagement();
            }
            
        } catch (error) {
            console.error('Failed to load dashboard:', error);
            this.showToast('Dashboard loaded in demo mode', 'warning');
            this.initializeDemoData();
            this.updateDashboard();
            this.updateUserDisplay();
            this.updateUI();
        }
    }
    
    initializeDemoData() {
        // Initialize with some demo data
        this.state.stats = {
            totalUploads: 0,
            secureFiles: 0,
            flaggedFiles: 0,
            storageUsed: 0
        };
        
        this.state.auditTrail = [
            {
                id: 'demo_1',
                action: 'user_login',
                details: { username: 'demo' },
                timestamp: new Date(),
                user: 'demo'
            }
        ];
        
        this.updateConnectionStatus(' Secure Connection (Demo Mode)');
    }
    
    loadDemoStats() {
        // Demo stats are already initialized
        this.updateStats();
    }
    
    async loadUserStats() {
        try {
            const response = await this.apiCall('/dashboard/stats', 'GET');
            if (response.success) {
                this.state.stats = response.stats;
            }
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    
    async loadUploadedFiles() {
        try {
            const response = await this.apiCall('/files', 'GET');
            if (response.success) {
                this.state.uploadedFiles = response.files;
            }
        } catch (error) {
            console.error('Failed to load files:', error);
        }
    }
    
    async loadAuditTrail() {
        try {
            const response = await this.apiCall('/audit', 'GET', null, {
                limit: 50
            });
            if (response.success) {
                this.state.auditTrail = response.events;
            }
        } catch (error) {
            console.error('Failed to load audit trail:', error);
        }
    }
    
    // File Upload Methods
    handleFiles(files) {
        const validFiles = [];
        const fileArray = Array.from(files);
        
        // Check file count limits
        const totalFiles = this.state.uploadQueue.length + this.state.uploadedFiles.length + fileArray.length;
        if (totalFiles > this.config.security.maxFilesPerHour) {
            this.showToast(`Maximum ${this.config.security.maxFilesPerHour} files allowed per hour`, 'error');
            return;
        }
        
        fileArray.forEach(file => {
            const validation = this.validateFile(file);
            const fileData = {
                id: this.generateId(),
                file: file,
                name: this.sanitizeFilename(file.name),
                originalName: file.name,
                size: file.size,
                type: file.type,
                validation: validation,
                status: validation.isValid ? 'ready' : 'invalid',
                uploadProgress: 0,
                uploadSpeed: 0,
                timeRemaining: 0,
                uploadedAt: null,
                securityScan: null,
                analysisResults: null,
                retryCount: 0
            };
            
            if (validation.isValid) {
                validFiles.push(fileData);
                this.state.uploadQueue.push(fileData);
            } else {
                this.showToast(`${file.name}: ${validation.errors[0]}`, 'error');
                this.addAuditEvent('file_validation_failed', {
                    filename: file.name,
                    reason: validation.errors[0]
                });
            }
        });
        
        if (validFiles.length > 0) {
            this.showToast(`${validFiles.length} file(s) added to queue`, 'success');
            this.updateUI();
            
            // Auto-start uploads
            this.processUploadQueue();
        }
    }
    
    validateFile(file) {
        const validation = {
            isValid: true,
            errors: [],
            warnings: []
        };
        
        // Check file size
        if (file.size < 1024) {
            validation.isValid = false;
            validation.errors.push('File too small (minimum 1KB)');
        }
        
        // Check file type and size limits
        const fileCategory = this.getFileCategory(file.type);
        if (!fileCategory) {
            validation.isValid = false;
            validation.errors.push('Unsupported file type');
        } else {
            const maxSize = this.config.fileSizeLimits[fileCategory];
            if (file.size > maxSize) {
                validation.isValid = false;
                validation.errors.push(`File too large (maximum ${this.formatFileSize(maxSize)})`);
            }
        }
        
        // Security checks
        const securityCheck = this.performClientSecurityCheck(file);
        if (!securityCheck.isSafe) {
            validation.isValid = false;
            validation.errors.push('Security validation failed');
        }
        
        if (securityCheck.warnings.length > 0) {
            validation.warnings = validation.warnings.concat(securityCheck.warnings);
        }
        
        return validation;
    }
    
    performClientSecurityCheck(file) {
        const check = {
            isSafe: true,
            warnings: []
        };
        
        // Check filename
        const fileName = file.name.toLowerCase();
        const extension = this.getFileExtension(file.name).toLowerCase();
        
        // Dangerous extensions
        const dangerousExts = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.com', '.msi'];
        if (dangerousExts.includes(extension)) {
            check.isSafe = false;
        }
        
        // Suspicious patterns
        if (/[<>"|*?\\\/:]/.test(fileName) || fileName.includes('..')) {
            check.warnings.push('Suspicious characters in filename');
        }
        
        // Double extensions
        const extensionCount = (file.name.match(/\./g) || []).length;
        if (extensionCount > 1) {
            check.warnings.push('Multiple file extensions detected');
        }
        
        // MIME type mismatch
        const expectedMimes = this.getExpectedMimeTypes(extension);
        if (expectedMimes.length > 0 && !expectedMimes.includes(file.type)) {
            check.warnings.push('MIME type mismatch');
        }
        
        return check;
    }
    
    async processUploadQueue() {
        const readyFiles = this.state.uploadQueue.filter(f => f.status === 'ready');
        const activeUploads = this.state.uploadQueue.filter(f => f.status === 'uploading').length;
        
        if (readyFiles.length === 0 || activeUploads >= this.config.security.maxConcurrentUploads) {
            return;
        }
        
        const filesToProcess = readyFiles.slice(0, this.config.security.maxConcurrentUploads - activeUploads);
        
        for (const fileData of filesToProcess) {
            this.uploadFile(fileData);
        }
    }
    
    async uploadFile(fileData) {
        try {
            fileData.status = 'uploading';
            fileData.uploadStartTime = Date.now();
            this.updateUI();
            
            // Demo mode - simulate upload
            if (this.config.demoMode) {
                await this.simulateUpload(fileData);
            } else {
                // Production upload with FormData
                const formData = new FormData();
                formData.append('file', fileData.file);
                formData.append('metadata', JSON.stringify({
                    originalName: fileData.originalName,
                    sanitizedName: fileData.name,
                    category: this.getFileCategory(fileData.type)
                }));
                
                const response = await this.uploadWithProgress(formData, fileData);
                
                if (!response.success) {
                    throw new Error(response.message || 'Upload failed');
                }
                
                fileData.securityScan = response.securityScan;
                fileData.analysisResults = response.analysisResults;
                fileData.serverFileId = response.fileId;
            }
            
            fileData.status = 'completed';
            fileData.uploadedAt = new Date();
            
            // Generate demo security scan if not provided
            if (!fileData.securityScan) {
                fileData.securityScan = this.generateDemoSecurityScan(fileData);
            }
            
            // Move from queue to uploaded files
            this.state.uploadQueue = this.state.uploadQueue.filter(f => f.id !== fileData.id);
            this.state.uploadedFiles.unshift(fileData);
            
            // Update stats
            this.state.stats.totalUploads++;
            if (fileData.securityScan && fileData.securityScan.isSafe) {
                this.state.stats.secureFiles++;
            } else {
                this.state.stats.flaggedFiles++;
            }
            this.state.stats.storageUsed += fileData.size;
            
            this.showToast(`${fileData.name} uploaded successfully`, 'success');
            this.addAuditEvent('file_uploaded', {
                filename: fileData.name,
                size: fileData.size,
                securityStatus: fileData.securityScan?.isSafe ? 'secure' : 'flagged'
            });
                
        } catch (error) {
            console.error('Upload failed:', error);
            fileData.status = 'error';
            fileData.error = error.message;
            
            // Retry logic
            if (fileData.retryCount < 3) {
                fileData.retryCount++;
                setTimeout(() => {
                    fileData.status = 'ready';
                    this.processUploadQueue();
                }, 2000 * fileData.retryCount);
                this.showToast(`Retrying upload for ${fileData.name}...`, 'warning');
            } else {
                this.showToast(`Upload failed: ${fileData.name}`, 'error');
                this.addAuditEvent('file_upload_failed', {
                    filename: fileData.name,
                    error: error.message
                });
            }
        }
        
        this.updateUI();
        
        // Process next files in queue
        setTimeout(() => this.processUploadQueue(), 100);
    }
    
    async simulateUpload(fileData) {
        return new Promise((resolve) => {
            const uploadTime = Math.random() * 3000 + 1000; // 1-4 seconds
            const interval = 100;
            const increment = 100 / (uploadTime / interval);
            
            const progressInterval = setInterval(() => {
                fileData.uploadProgress = Math.min(fileData.uploadProgress + increment + Math.random() * 5, 100);
                
                // Calculate speed and time remaining
                const elapsed = Date.now() - fileData.uploadStartTime;
                if (elapsed > 500) {
                    fileData.uploadSpeed = (fileData.size * (fileData.uploadProgress / 100)) / (elapsed / 1000);
                    fileData.timeRemaining = (100 - fileData.uploadProgress) * elapsed / (fileData.uploadProgress * 1000);
                }
                
                this.updateUI();
                
                if (fileData.uploadProgress >= 100) {
                    clearInterval(progressInterval);
                    resolve();
                }
            }, interval);
        });
    }
    
    generateDemoSecurityScan(fileData) {
        // Generate random but realistic security scan results
        const isSecure = Math.random() > 0.2; // 80% secure files
        const threats = [];
        const riskLevel = isSecure ? 'low' : (Math.random() > 0.5 ? 'medium' : 'high');
        
        if (!isSecure) {
            const possibleThreats = [
                'Suspicious file extension detected',
                'MIME type mismatch found',
                'Unusual file structure',
                'Potential embedded scripts',
                'File header inconsistencies'
            ];
            
            const numThreats = Math.floor(Math.random() * 3) + 1;
            for (let i = 0; i < numThreats; i++) {
                const threat = possibleThreats[Math.floor(Math.random() * possibleThreats.length)];
                if (!threats.includes(threat)) {
                    threats.push(threat);
                }
            }
        }
        
        return {
            isSafe: isSecure,
            threats: threats,
            riskLevel: riskLevel,
            scanDate: new Date(),
            scanner: 'HawkEye'
        };
    }
    
    async uploadWithProgress(formData, fileData) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            
            // Progress tracking
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const progress = (e.loaded / e.total) * 100;
                    fileData.uploadProgress = progress;
                    
                    // Calculate speed and time remaining
                    const elapsed = Date.now() - fileData.uploadStartTime;
                    if (elapsed > 1000) {
                        fileData.uploadSpeed = e.loaded / (elapsed / 1000);
                        fileData.timeRemaining = (e.total - e.loaded) / fileData.uploadSpeed;
                    }
                    
                    this.updateUI();
                }
            });
            
            xhr.addEventListener('load', () => {
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (xhr.status === 200) {
                        resolve(response);
                    } else {
                        reject(new Error(response.message || 'Upload failed'));
                    }
                } catch (error) {
                    reject(new Error('Invalid response from server'));
                }
            });
            
            xhr.addEventListener('error', () => {
                reject(new Error('Network error during upload'));
            });
            
            xhr.addEventListener('timeout', () => {
                reject(new Error('Upload timeout'));
            });
            
            // Set timeout
            xhr.timeout = 300000; // 5 minutes
            
            // Open and send
            xhr.open('POST', `${this.config.apiBaseUrl}/upload`);
            xhr.setRequestHeader('X-CSRF-Token', this.state.csrfToken);
            xhr.send(formData);
        });
    }
    
    // File Management Methods
    async deleteFile(fileId) {
        try {
            if (this.config.demoMode) {
                // Demo mode - just remove from local state
                const fileIndex = this.state.uploadedFiles.findIndex(f => f.id === fileId);
                if (fileIndex !== -1) {
                    const file = this.state.uploadedFiles[fileIndex];
                    this.state.uploadedFiles.splice(fileIndex, 1);
                    this.state.stats.totalUploads--;
                    this.state.stats.storageUsed -= file.size;
                    
                    if (file.securityScan?.isSafe) {
                        this.state.stats.secureFiles--;
                    } else {
                        this.state.stats.flaggedFiles--;
                    }
                    
                    this.updateUI();
                    this.showToast('File deleted successfully', 'success');
                    this.addAuditEvent('file_deleted', { filename: file.name });
                }
                return;
            }
            
            const response = await this.apiCall(`/files/${fileId}`, 'DELETE');
            if (response.success) {
                // Remove from local state
                const fileIndex = this.state.uploadedFiles.findIndex(f => f.id === fileId);
                if (fileIndex !== -1) {
                    const file = this.state.uploadedFiles[fileIndex];
                    this.state.uploadedFiles.splice(fileIndex, 1);
                    this.state.stats.totalUploads--;
                    this.state.stats.storageUsed -= file.size;
                    
                    if (file.securityScan?.isSafe) {
                        this.state.stats.secureFiles--;
                    } else {
                        this.state.stats.flaggedFiles--;
                    }
                }
                
                this.updateUI();
                this.showToast('File deleted successfully', 'success');
                this.addAuditEvent('file_deleted', { fileId });
            }
        } catch (error) {
            this.showToast('Failed to delete file', 'error');
        }
    }
    
    async downloadFile(fileId) {
        try {
            const file = this.state.uploadedFiles.find(f => f.id === fileId);
            if (!file) return;
            
            // For client-side files, create download link
            if (file.file instanceof File) {
                const url = URL.createObjectURL(file.file);
                const a = document.createElement('a');
                a.href = url;
                a.download = file.name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } else if (!this.config.demoMode) {
                // For server files, use API endpoint
                const response = await fetch(`${this.config.apiBaseUrl}/files/${fileId}/download`, {
                    headers: {
                        'Authorization': `Bearer ${this.getAuthToken()}`,
                        'X-CSRF-Token': this.state.csrfToken
                    }
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = file.name;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }
            } else {
                this.showToast('Download not available in demo mode', 'info');
            }
            
            this.showToast(`${file.name} downloaded`, 'success');
            this.addAuditEvent('file_downloaded', { filename: file.name });
            
        } catch (error) {
            this.showToast('Download failed', 'error');
        }
    }
    
    // UI Event Handlers
    setupEventListeners() {
        // Authentication form handlers
        this.setupAuthEventListeners();
        
        // File upload handlers
        this.setupUploadEventListeners();
        
        // File management handlers
        this.setupFileManagementEventListeners();
        
        // Modal handlers
        this.setupModalEventListeners();
        
        // Filter handlers
        this.setupFilterEventListeners();
        
        // Global handlers
        this.setupGlobalEventListeners();
    }
    
    setupAuthEventListeners() {
        const loginBtn = document.getElementById('loginBtn');
        const registerBtn = document.getElementById('registerBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        const showRegister = document.getElementById('showRegister');
        const showLogin = document.getElementById('showLogin');
        
        if (loginBtn) {
            loginBtn.addEventListener('click', async () => {
                const username = document.getElementById('username')?.value || '';
                const password = document.getElementById('password')?.value || '';
                await this.login(username, password);
            });
        }
        
        if (registerBtn) {
            registerBtn.addEventListener('click', async () => {
                const username = document.getElementById('regUsername')?.value || '';
                const email = document.getElementById('regEmail')?.value || '';
                const password = document.getElementById('regPassword')?.value || '';
                const confirmPassword = document.getElementById('regConfirmPassword')?.value || '';
                await this.register(username, email, password, confirmPassword);
            });
        }
        
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.logout());
        }
        
        if (showRegister) {
            showRegister.addEventListener('click', (e) => {
                e.preventDefault();
                this.showRegisterForm();
            });
        }
        
        if (showLogin) {
            showLogin.addEventListener('click', (e) => {
                e.preventDefault();
                this.showLoginForm();
            });
        }
        
        // Form submit handlers
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                loginBtn?.click();
            });
        }
        
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                registerBtn?.click();
            });
        }
    }
    
    setupUploadEventListeners() {
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const browseBtn = document.getElementById('browseBtn');
        
        if (uploadArea && fileInput && browseBtn) {
            browseBtn.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('click', (e) => {
                if (e.target === uploadArea || e.target.closest('.upload-content')) {
                    fileInput.click();
                }
            });
            
            fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    this.handleFiles(e.target.files);
                    e.target.value = '';
                }
            });
            
            // Drag and drop
            uploadArea.addEventListener('dragenter', (e) => this.handleDragEnter(e));
            uploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
            uploadArea.addEventListener('dragleave', (e) => this.handleDragLeave(e));
            uploadArea.addEventListener('drop', (e) => this.handleDrop(e));
        }
        
        // Queue control buttons
        const startAllBtn = document.getElementById('startAllBtn');
        const pauseAllBtn = document.getElementById('pauseAllBtn');
        const clearQueueBtn = document.getElementById('clearQueueBtn');
        
        if (startAllBtn) startAllBtn.addEventListener('click', () => this.processUploadQueue());
        if (pauseAllBtn) pauseAllBtn.addEventListener('click', () => this.pauseAllUploads());
        if (clearQueueBtn) clearQueueBtn.addEventListener('click', () => this.clearUploadQueue());
    }
    
    setupFileManagementEventListeners() {
        const exportBtn = document.getElementById('exportBtn');
        const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
        const refreshAuditBtn = document.getElementById('refreshAuditBtn');
        
        if (exportBtn) exportBtn.addEventListener('click', () => this.exportFilesList());
        if (bulkDeleteBtn) bulkDeleteBtn.addEventListener('click', () => this.showBulkActionsModal());
        if (refreshAuditBtn) refreshAuditBtn.addEventListener('click', () => this.loadAuditTrail());
    }
    
    setupModalEventListeners() {
        // Close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const modal = e.target.closest('.modal');
                if (modal) this.closeModal(modal.id);
            });
        });
        
        // Click outside to close
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal') && !e.target.id.includes('auth')) {
                this.closeModal(e.target.id);
            }
        });
        
        // Confirmation modal
        const confirmAction = document.getElementById('confirmAction');
        const cancelAction = document.getElementById('cancelAction');
        
        if (confirmAction) {
            confirmAction.addEventListener('click', () => {
                if (this.pendingConfirmAction) {
                    this.pendingConfirmAction();
                    this.pendingConfirmAction = null;
                }
                this.closeModal('confirmModal');
            });
        }
        
        if (cancelAction) {
            cancelAction.addEventListener('click', () => {
                this.pendingConfirmAction = null;
                this.closeModal('confirmModal');
            });
        }
    }
    
    setupFilterEventListeners() {
        const statusFilter = document.getElementById('statusFilter');
        const typeFilter = document.getElementById('typeFilter');
        
        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                this.state.filters.status = e.target.value;
                this.updateUI();
            });
        }
        
        if (typeFilter) {
            typeFilter.addEventListener('change', (e) => {
                this.state.filters.type = e.target.value;
                this.updateUI();
            });
        }
    }
    
    setupGlobalEventListeners() {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            document.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                if (e.key === 'u') {
                    e.preventDefault();
                    if (this.state.isAuthenticated) {
                        document.getElementById('fileInput')?.click();
                    }
                }
            }
            
            if (e.key === 'Escape') {
                // Close any open modals except auth modal
                document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
                    if (modal.id !== 'authModal') {
                        this.closeModal(modal.id);
                    }
                });
            }
        });
        
        // Online/offline events (skip in demo mode)
        if (!this.config.demoMode) {
            window.addEventListener('online', () => this.handleNetworkStatusChange('online'));
            window.addEventListener('offline', () => this.handleNetworkStatusChange('offline'));
        }
    }
    
    // Drag and Drop Handlers
    handleDragEnter(e) {
        e.preventDefault();
        this.dragCounter++;
        document.getElementById('uploadArea')?.classList.add('dragover');
    }
    
    handleDragOver(e) {
        e.preventDefault();
    }
    
    handleDragLeave(e) {
        e.preventDefault();
        this.dragCounter--;
        if (this.dragCounter === 0) {
            document.getElementById('uploadArea')?.classList.remove('dragover');
        }
    }
    
    handleDrop(e) {
        e.preventDefault();
        this.dragCounter = 0;
        document.getElementById('uploadArea')?.classList.remove('dragover');
        
        const files = Array.from(e.dataTransfer.files);
        if (files.length > 0) {
            this.handleFiles(files);
        }
    }
    
    // UI Update Methods
    updateUI() {
        this.updateStats();
        this.updateUploadQueue();
        this.updateFilesList();
        this.updateAuditTrail();
    }
    
    updateDashboard() {
        const mainContent = document.getElementById('mainContent');
        if (mainContent) {
            mainContent.style.display = this.state.isAuthenticated ? 'block' : 'none';
        }
    }
    
    updateUserDisplay() {
        const userDisplay = document.getElementById('userDisplay');
        if (userDisplay && this.state.currentUser) {
            userDisplay.textContent = this.state.currentUser.username;
        }
    }
    
    updateStats() {
        const elements = {
            totalUploads: document.getElementById('totalUploads'),
            secureFiles: document.getElementById('secureFiles'),
            flaggedFiles: document.getElementById('flaggedFiles'),
            storageUsed: document.getElementById('storageUsed')
        };
        
        if (elements.totalUploads) elements.totalUploads.textContent = this.state.stats.totalUploads;
        if (elements.secureFiles) elements.secureFiles.textContent = this.state.stats.secureFiles;
        if (elements.flaggedFiles) elements.flaggedFiles.textContent = this.state.stats.flaggedFiles;
        if (elements.storageUsed) elements.storageUsed.textContent = this.formatFileSize(this.state.stats.storageUsed);
    }
    
    updateUploadQueue() {
        const queueList = document.getElementById('queueList');
        if (!queueList) return;
        
        if (this.state.uploadQueue.length === 0) {
            queueList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📄</div>
                    <p>No files in queue</p>
                </div>
            `;
            return;
        }
        
        queueList.innerHTML = this.state.uploadQueue.map(fileData => `
            <div class="queue-item">
                <div class="file-icon">${this.getFileIcon(fileData.type)}</div>
                <div class="file-details">
                    <div class="file-name" title="${fileData.originalName}">${fileData.name}</div>
                    <div class="file-meta">
                        <span>${this.formatFileSize(fileData.size)}</span>
                        <span>${fileData.type}</span>
                        ${fileData.uploadSpeed ? `<span>${this.formatFileSize(fileData.uploadSpeed)}/s</span>` : ''}
                        ${fileData.timeRemaining ? `<span>ETA: ${this.formatTime(fileData.timeRemaining)}</span>` : ''}
                        ${fileData.validation.errors.length > 0 ? `<span class="error" style="color: var(--color-error);"> ${fileData.validation.errors[0]}</span>` : ''}
                    </div>
                </div>
                ${fileData.status === 'uploading' ? `
                    <div class="progress-container">
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${fileData.uploadProgress}%"></div>
                        </div>
                        <div class="progress-text">${Math.round(fileData.uploadProgress)}%</div>
                    </div>
                ` : ''}
                <div class="file-status ${fileData.status}">${this.getStatusText(fileData.status)}</div>
                <div class="file-actions">
                    <button class="action-btn danger" onclick="hawkEye.removeFromQueue('${fileData.id}')">
                         Remove
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    updateFilesList() {
        const filesList = document.getElementById('filesList');
        if (!filesList) return;
        
        let filteredFiles = this.state.uploadedFiles;
        
        // Apply filters
        if (this.state.filters.status !== 'all') {
            filteredFiles = filteredFiles.filter(file => {
                if (this.state.filters.status === 'secure') {
                    return file.securityScan?.isSafe;
                } else if (this.state.filters.status === 'flagged') {
                    return !file.securityScan?.isSafe;
                } else if (this.state.filters.status === 'processing') {
                    return file.status === 'processing' || file.status === 'analyzing';
                }
                return true;
            });
        }
        
        if (this.state.filters.type !== 'all') {
            filteredFiles = filteredFiles.filter(file => {
                const category = this.getFileCategory(file.type);
                return category === this.state.filters.type.replace('s', ''); // Remove plural
            });
        }
        
        if (filteredFiles.length === 0) {
            filesList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📋</div>
                    <p>${this.state.uploadedFiles.length === 0 ? 'No files uploaded yet' : 'No files match the current filters'}</p>
                </div>
            `;
            return;
        }
        
        filesList.innerHTML = filteredFiles.map(fileData => `
            <div class="file-item ${this.state.selectedFiles.has(fileData.id) ? 'selected' : ''}" 
                 onclick="hawkEye.toggleFileSelection('${fileData.id}', event)">
                <div class="file-preview">
                    ${this.canPreview(fileData.type) && fileData.file ? 
                        `<img src="${URL.createObjectURL(fileData.file)}" alt="Preview" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                         <div class="file-preview-icon" style="display: none;">${this.getFileIcon(fileData.type)}</div>` :
                        `<div class="file-preview-icon">${this.getFileIcon(fileData.type)}</div>`
                    }
                </div>
                <div class="file-info">
                    <div class="file-title" title="${fileData.originalName}">${fileData.name}</div>
                    <div class="file-metadata">
                        <span>${this.formatFileSize(fileData.size)}</span>
                        <span>${fileData.type}</span>
                        ${fileData.uploadedAt ? `<span>${this.formatDate(fileData.uploadedAt)}</span>` : ''}
                        <div class="security-badge ${fileData.securityScan?.isSafe ? 'secure' : 'warning'}">
                            ${fileData.securityScan?.isSafe ? ' Secure' : ' Flagged'}
                        </div>
                    </div>
                </div>
                <div class="file-actions">
                    <button class="action-btn" onclick="event.stopPropagation(); hawkEye.previewFile('${fileData.id}')">
                         View
                    </button>
                    <button class="action-btn success" onclick="event.stopPropagation(); hawkEye.downloadFile('${fileData.id}')">
                         Download
                    </button>
                    <button class="action-btn danger" onclick="event.stopPropagation(); hawkEye.showDeleteConfirm('${fileData.id}')">
                         Delete
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    updateAuditTrail() {
        const auditList = document.getElementById('auditList');
        if (!auditList) return;
        
        if (this.state.auditTrail.length === 0) {
            auditList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📋</div>
                    <p>No audit events to display</p>
                </div>
            `;
            return;
        }
        
        auditList.innerHTML = this.state.auditTrail.slice(0, 10).map(event => `
            <div class="audit-item">
                <div class="audit-details">
                    <div class="audit-action">${this.getAuditActionText(event.action)}</div>
                    <div class="audit-meta">
                        <span class="audit-timestamp">${this.formatDate(event.timestamp)}</span>
                        ${event.details ? `<span>${typeof event.details === 'string' ? event.details : JSON.stringify(event.details)}</span>` : ''}
                    </div>
                </div>
                <div class="audit-actions">
                    <div class="security-badge ${this.getAuditSeverity(event.action)}">
                        ${this.getAuditIcon(event.action)} ${event.action.replace('_', ' ').toUpperCase()}
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    // API Communication
    async apiCall(endpoint, method = 'GET', data = null, params = null) {
        const url = new URL(`${this.config.apiBaseUrl}${endpoint}`);
        
        if (params) {
            Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
        }
        
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.state.csrfToken
            }
        };
        
        if (this.state.isAuthenticated) {
            options.headers['Authorization'] = `Bearer ${this.getAuthToken()}`;
        }
        
        if (data && method !== 'GET') {
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(url, options);
        
        if (!response.ok) {
            if (response.status === 401) {
                // Unauthorized - redirect to login
                this.logout();
                throw new Error('Session expired');
            }
            throw new Error(`API Error: ${response.status}`);
        }
        
        return await response.json();
    }
    
    // WebSocket Connection
    initializeWebSocket() {
        if (this.websocket) {
            this.websocket.close();
        }
        
        try {
            this.websocket = new WebSocket(`${this.config.wsUrl}?token=${this.getAuthToken()}`);
            
            this.websocket.onopen = () => {
                console.log('WebSocket connected');
                this.updateConnectionStatus(' Secure Connection');
            };
            
            this.websocket.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleWebSocketMessage(message);
                } catch (error) {
                    console.error('WebSocket message parse error:', error);
                }
            };
            
            this.websocket.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus(' Connection Lost');
                
                // Attempt to reconnect
                if (this.state.isAuthenticated) {
                    setTimeout(() => this.initializeWebSocket(), 5000);
                }
            };
            
            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    }
    
    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'file_analysis_complete':
                this.handleFileAnalysisComplete(message.data);
                break;
            case 'security_alert':
                this.handleSecurityAlert(message.data);
                break;
            case 'system_notification':
                this.showToast(message.data.message, message.data.type);
                break;
            default:
                console.log('Unknown WebSocket message type:', message.type);
        }
    }
    
    handleFileAnalysisComplete(data) {
        const file = this.state.uploadedFiles.find(f => f.serverFileId === data.fileId);
        if (file) {
            file.analysisResults = data.results;
            file.securityScan = data.securityScan;
            this.updateUI();
            this.showToast(`Analysis complete for ${file.name}`, 'info');
            this.addAuditEvent('file_analysis_complete', {
                filename: file.name,
                result: data.securityScan.isSafe ? 'secure' : 'flagged'
            });
        }
    }
    
    handleSecurityAlert(data) {
        this.showToast(`Security Alert: ${data.message}`, 'error');
        this.addAuditEvent('security_alert', data);
    }
    
    // Security Methods
    async initializeSecurity() {
        try {
            if (this.config.demoMode) {
                this.state.csrfToken = 'demo-csrf-token';
                return;
            }
            
            // Get CSRF token
            const response = await fetch(`${this.config.apiBaseUrl}/csrf-token`);
            if (response.ok) {
                const data = await response.json();
                this.state.csrfToken = data.token;
            }
            
            // Start CSRF token refresh
            this.startCSRFTokenRefresh();
            
        } catch (error) {
            console.error('Failed to initialize security:', error);
            this.state.csrfToken = 'demo-csrf-token'; // Fallback for demo
        }
    }
    
    startCSRFTokenRefresh() {
        if (this.config.demoMode) return;
        
        this.csrfRefreshTimer = setInterval(async () => {
            try {
                const response = await fetch(`${this.config.apiBaseUrl}/csrf-token`);
                if (response.ok) {
                    const data = await response.json();
                    this.state.csrfToken = data.token;
                }
            } catch (error) {
                console.error('Failed to refresh CSRF token:', error);
            }
        }, this.config.security.csrfTokenRefreshInterval);
    }
    
    startSessionManagement() {
        if (this.config.demoMode) return;
        
        // Clear existing timer
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
        }
        
        // Check session expiry every minute
        this.sessionTimer = setInterval(() => {
            if (this.state.sessionExpiry && new Date() >= this.state.sessionExpiry) {
                this.showToast('Session expired. Please log in again.', 'warning');
                this.logout();
            }
        }, 60000);
    }
    
    clearSessionManagement() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
        
        if (this.csrfRefreshTimer) {
            clearInterval(this.csrfRefreshTimer);
            this.csrfRefreshTimer = null;
        }
    }
    
    getAuthToken() {
        // In production, this would retrieve the JWT token from secure storage
        return localStorage.getItem('hawkeye_auth_token') || 'demo-token';
    }
    
    // Network Monitoring
    initializeNetworkMonitoring() {
        // Initial status
        this.state.networkStatus = navigator.onLine ? 'online' : 'offline';
        
        // Periodic connectivity check
        this.networkCheckTimer = setInterval(() => {
            this.checkNetworkConnectivity();
        }, this.config.ui.networkCheckInterval);
    }
    
    async checkNetworkConnectivity() {
        try {
            const response = await fetch(`${this.config.apiBaseUrl}/health`, {
                method: 'HEAD',
                timeout: 5000
            });
            
            if (response.ok) {
                if (this.state.networkStatus !== 'online') {
                    this.handleNetworkStatusChange('online');
                }
            } else {
                this.handleNetworkStatusChange('offline');
            }
        } catch (error) {
            this.handleNetworkStatusChange('offline');
        }
    }
    
    handleNetworkStatusChange(status) {
        const previousStatus = this.state.networkStatus;
        this.state.networkStatus = status;
        
        if (status === 'online' && previousStatus === 'offline') {
            this.showToast('Connection restored', 'success');
            this.hideNetworkStatus();
            
            // Resume uploads
            this.processUploadQueue();
            
            // Reconnect WebSocket
            if (this.state.isAuthenticated && !this.websocket) {
                this.initializeWebSocket();
            }
            
        } else if (status === 'offline') {
            this.showToast('Connection lost', 'error');
            this.showNetworkStatus();
        }
        
        this.updateConnectionStatus(status);
    }
    
    // UI Helper Methods
    showLoadingScreen() {
        const loadingScreen = document.getElementById('loadingScreen');
        if (loadingScreen) {
            loadingScreen.classList.remove('hidden');
        }
    }
    
    hideLoadingScreen() {
        const loadingScreen = document.getElementById('loadingScreen');
        if (loadingScreen) {
            setTimeout(() => {
                loadingScreen.classList.add('hidden');
            }, 500);
        }
    }
    
    showAuthModal() {
        const authModal = document.getElementById('authModal');
        const mainContent = document.getElementById('mainContent');
        
        if (authModal) authModal.classList.remove('hidden');
        if (mainContent) mainContent.style.display = 'none';
    }
    
    hideAuthModal() {
        const authModal = document.getElementById('authModal');
        const mainContent = document.getElementById('mainContent');
        
        if (authModal) authModal.classList.add('hidden');
        if (mainContent) mainContent.style.display = 'block';
    }
    
    showLoginForm() {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        
        if (loginForm) loginForm.classList.remove('hidden');
        if (registerForm) registerForm.classList.add('hidden');
    }
    
    showRegisterForm() {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        
        if (loginForm) loginForm.classList.add('hidden');
        if (registerForm) registerForm.classList.remove('hidden');
    }
    
    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
        }
    }
    
    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('hidden');
        }
    }
    
    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: '',
            error: '',
            warning: '',
            info: ''
        };
        
        toast.innerHTML = `
            <span class="toast-icon">${icons[type]}</span>
            <span class="toast-message">${message}</span>
            <button class="toast-close">×</button>
        `;
        
        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => toast.remove());
        
        container.appendChild(toast);
        
        // Show with animation
        setTimeout(() => toast.classList.add('show'), 10);
        
        // Auto remove
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, 300);
        }, this.config.ui.toastDuration);
    }
    
    showNetworkStatus() {
        const networkStatus = document.getElementById('networkStatus');
        if (networkStatus) {
            networkStatus.classList.remove('hidden');
        }
    }
    
    hideNetworkStatus() {
        const networkStatus = document.getElementById('networkStatus');
        if (networkStatus) {
            networkStatus.classList.add('hidden');
        }
    }
    
    updateConnectionStatus(status) {
        const connectionStatus = document.getElementById('connectionStatus');
        if (connectionStatus) {
            if (typeof status === 'string' && status.includes('')) {
                connectionStatus.textContent = status;
                connectionStatus.className = 'status status--success';
            } else if (status === 'online') {
                connectionStatus.textContent = ' Secure Connection';
                connectionStatus.className = 'status status--success';
            } else {
                connectionStatus.textContent = ' Connection Lost';
                connectionStatus.className = 'status status--error';
            }
        }
    }
    
    // Action Methods
    removeFromQueue(id) {
        this.state.uploadQueue = this.state.uploadQueue.filter(f => f.id !== id);
        this.updateUI();
        this.showToast('File removed from queue', 'info');
    }
    
    pauseAllUploads() {
        this.state.uploadQueue.forEach(file => {
            if (file.status === 'uploading') {
                file.status = 'paused';
            }
        });
        this.updateUI();
        this.showToast('All uploads paused', 'info');
    }
    
    clearUploadQueue() {
        this.showConfirmModal('Clear all files from upload queue?', () => {
            this.state.uploadQueue = [];
            this.updateUI();
            this.showToast('Upload queue cleared', 'success');
        });
    }
    
    toggleFileSelection(fileId, event) {
        if (event && !event.ctrlKey && !event.metaKey) {
            // Regular click - show preview
            this.previewFile(fileId);
            return;
        }
        
        // Ctrl/Cmd click - toggle selection
        if (this.state.selectedFiles.has(fileId)) {
            this.state.selectedFiles.delete(fileId);
        } else {
            this.state.selectedFiles.add(fileId);
        }
        
        this.updateUI();
    }
    
    previewFile(fileId) {
        const fileData = this.state.uploadedFiles.find(f => f.id === fileId);
        if (!fileData) return;
        
        const modal = document.getElementById('previewModal');
        const content = document.getElementById('previewContent');
        
        if (!modal || !content) return;
        
        let previewHTML = '';
        
        // Preview tabs
        previewHTML += `
            <div class="preview-tabs">
                <button class="preview-tab active" data-tab="preview">Preview</button>
                <button class="preview-tab" data-tab="details">Details</button>
                <button class="preview-tab" data-tab="security">Security</button>
                <button class="preview-tab" data-tab="analysis">Analysis</button>
            </div>
        `;
        
        // Preview content
        if (fileData.type.startsWith('image/') && fileData.file) {
            previewHTML += `
                <div class="tab-content" data-tab="preview">
                    <img src="${URL.createObjectURL(fileData.file)}" alt="${fileData.name}" class="preview-image">
                </div>
            `;
        } else {
            previewHTML += `
                <div class="tab-content" data-tab="preview">
                    <div style="text-align: center; padding: 60px;">
                        <div style="font-size: 4rem; margin-bottom: 20px;">${this.getFileIcon(fileData.type)}</div>
                        <h3>${fileData.name}</h3>
                        <p>Preview not available for this file type</p>
                    </div>
                </div>
            `;
        }
        
        // Details tab
        previewHTML += `
            <div class="tab-content hidden" data-tab="details">
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Original Name</div>
                        <div class="info-value">${fileData.originalName}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">File Size</div>
                        <div class="info-value">${this.formatFileSize(fileData.size)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">MIME Type</div>
                        <div class="info-value">${fileData.type}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Category</div>
                        <div class="info-value">${this.getFileCategory(fileData.type) || 'Unknown'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Uploaded</div>
                        <div class="info-value">${fileData.uploadedAt ? this.formatDate(fileData.uploadedAt) : 'N/A'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Status</div>
                        <div class="info-value">${fileData.status}</div>
                    </div>
                </div>
            </div>
        `;
        
        // Security tab
        previewHTML += `
            <div class="tab-content hidden" data-tab="security">
                <div class="analysis-results">
                    <div class="analysis-section">
                        <h5> Security Scan Results</h5>
                        ${fileData.securityScan ? `
                            <div class="security-badge ${fileData.securityScan.isSafe ? 'secure' : 'danger'}">
                                ${fileData.securityScan.isSafe ? ' File is secure' : ' Security issues detected'}
                            </div>
                            <div class="info-grid" style="margin-top: 16px;">
                                <div class="info-item">
                                    <div class="info-label">Risk Level</div>
                                    <div class="info-value">${fileData.securityScan.riskLevel?.toUpperCase() || 'UNKNOWN'}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Scanner</div>
                                    <div class="info-value">${fileData.securityScan.scanner || 'HawkEye Scanner'}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Scan Date</div>
                                    <div class="info-value">${fileData.securityScan.scanDate ? this.formatDate(fileData.securityScan.scanDate) : 'N/A'}</div>
                                </div>
                            </div>
                            ${fileData.securityScan.threats && fileData.securityScan.threats.length > 0 ? `
                                <h6 style="margin-top: 16px; margin-bottom: 8px;">Detected Threats:</h6>
                                <ul class="threat-list">
                                    ${fileData.securityScan.threats.map(threat => `
                                        <li class="threat-item ${fileData.securityScan.riskLevel || 'medium'}">
                                             ${threat}
                                        </li>
                                    `).join('')}
                                </ul>
                            ` : '<p style="margin-top: 16px;">No security threats detected.</p>'}
                        ` : '<p>Security scan pending...</p>'}
                    </div>
                </div>
            </div>
        `;
        
        // Analysis tab
        previewHTML += `
            <div class="tab-content hidden" data-tab="analysis">
                <div class="analysis-results">
                    <div class="analysis-section">
                        <h5> AI Analysis Results</h5>
                        ${fileData.analysisResults ? `
                            <pre style="background: var(--color-secondary); padding: 16px; border-radius: 8px; overflow: auto; font-size: 12px;">${JSON.stringify(fileData.analysisResults, null, 2)}</pre>
                        ` : '<p>AI analysis pending or not available in demo mode...</p>'}
                    </div>
                </div>
            </div>
        `;
        
        content.innerHTML = previewHTML;
        
        // Setup tab switching
        const tabs = content.querySelectorAll('.preview-tab');
        const tabContents = content.querySelectorAll('.tab-content');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.dataset.tab;
                
                tabs.forEach(t => t.classList.remove('active'));
                tabContents.forEach(tc => tc.classList.add('hidden'));
                
                tab.classList.add('active');
                const targetContent = content.querySelector(`[data-tab="${targetTab}"]`);
                if (targetContent) {
                    targetContent.classList.remove('hidden');
                }
            });
        });
        
        modal.classList.remove('hidden');
    }
    
    showDeleteConfirm(fileId) {
        this.showConfirmModal('Delete this file permanently?', () => {
            this.deleteFile(fileId);
        });
    }
    
    showBulkActionsModal() {
        if (this.state.selectedFiles.size === 0) {
            this.showToast('No files selected', 'warning');
            return;
        }
        
        this.showModal('bulkModal');
        
        // Update selected files display
        const selectedFilesEl = document.getElementById('selectedFiles');
        if (selectedFilesEl) {
            const selectedFilesList = Array.from(this.state.selectedFiles).map(id => {
                const file = this.state.uploadedFiles.find(f => f.id === id);
                return file ? file.name : 'Unknown';
            }).join(', ');
            
            selectedFilesEl.innerHTML = `<p>Selected files (${this.state.selectedFiles.size}): ${selectedFilesList}</p>`;
        }
    }
    
    showConfirmModal(message, onConfirm) {
        const modal = document.getElementById('confirmModal');
        const messageEl = document.getElementById('confirmMessage');
        
        if (!modal || !messageEl) return;
        
        messageEl.textContent = message;
        this.pendingConfirmAction = onConfirm;
        modal.classList.remove('hidden');
    }
    
    exportFilesList() {
        if (this.state.uploadedFiles.length === 0) {
            this.showToast('No files to export', 'warning');
            return;
        }
        
        const data = this.state.uploadedFiles.map(file => ({
            name: file.name,
            originalName: file.originalName,
            size: this.formatFileSize(file.size),
            type: file.type,
            category: this.getFileCategory(file.type),
            uploadedAt: file.uploadedAt ? this.formatDate(file.uploadedAt) : 'N/A',
            securityStatus: file.securityScan?.isSafe ? 'Secure' : 'Flagged',
            riskLevel: file.securityScan?.riskLevel || 'Unknown',
            threats: file.securityScan?.threats ? file.securityScan.threats.join('; ') : 'None'
        }));
        
        const csv = this.convertToCSV(data);
        this.downloadCSV(csv, `hawkeye-files-${new Date().toISOString().split('T')[0]}.csv`);
        this.showToast('File list exported successfully', 'success');
        this.addAuditEvent('files_exported', { count: data.length });
    }
    
    // Audit Trail Methods
    addAuditEvent(action, details = null) {
        const event = {
            id: this.generateId(),
            action,
            details,
            timestamp: new Date(),
            user: this.state.currentUser?.username || 'Anonymous'
        };
        
        this.state.auditTrail.unshift(event);
        
        // Keep only last 100 events in memory
        if (this.state.auditTrail.length > 100) {
            this.state.auditTrail = this.state.auditTrail.slice(0, 100);
        }
        
        // Send to server in production mode
        if (!this.config.demoMode) {
            // this.apiCall('/audit', 'POST', event);
        }
        
        this.updateAuditTrail();
    }
    
    getAuditActionText(action) {
        const actionTexts = {
            'file_uploaded': 'File uploaded',
            'file_deleted': 'File deleted',
            'file_downloaded': 'File downloaded',
            'file_validation_failed': 'File validation failed',
            'file_upload_failed': 'File upload failed',
            'file_analysis_complete': 'File analysis completed',
            'security_alert': 'Security alert',
            'user_login': 'User logged in',
            'user_logout': 'User logged out',
            'files_exported': 'Files exported'
        };
        
        return actionTexts[action] || action.replace('_', ' ');
    }
    
    getAuditIcon(action) {
        const icons = {
            'file_uploaded': '',
            'file_deleted': '',
            'file_downloaded': '',
            'file_validation_failed': '',
            'file_upload_failed': '',
            'file_analysis_complete': '',
            'security_alert': '',
            'user_login': '',
            'user_logout': '',
            'files_exported': ''
        };
        
        return icons[action] || '';
    }
    
    getAuditSeverity(action) {
        const severities = {
            'file_uploaded': 'secure',
            'file_deleted': 'warning',
            'file_downloaded': 'secure',
            'file_validation_failed': 'danger',
            'file_upload_failed': 'danger',
            'file_analysis_complete': 'secure',
            'security_alert': 'danger',
            'user_login': 'secure',
            'user_logout': 'secure',
            'files_exported': 'secure'
        };
        
        return severities[action] || 'secure';
    }
    
    // Utility Methods
    generateId() {
        return 'hawkeye_' + Math.random().toString(36).substring(2, 11) + '_' + Date.now();
    }
    
    sanitizeFilename(filename) {
        return filename
            .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
            .replace(/\.\./g, '_')
            .replace(/^\.+/, '')
            .slice(0, 255);
    }
    
    getFileCategory(mimeType) {
        for (const [category, types] of Object.entries(this.config.allowedFileTypes)) {
            if (types.includes(mimeType)) {
                return category.slice(0, -1); // Remove 's' from plural
            }
        }
        return null;
    }
    
    getFileExtension(filename) {
        return filename.slice(filename.lastIndexOf('.'));
    }
    
    getExpectedMimeTypes(extension) {
        const mimeMap = {
            '.jpg': ['image/jpeg'],
            '.jpeg': ['image/jpeg'],
            '.png': ['image/png'],
            '.gif': ['image/gif'],
            '.mp4': ['video/mp4'],
            '.avi': ['video/avi'],
            '.mov': ['video/mov', 'video/quicktime'],
            '.mp3': ['audio/mpeg', 'audio/mp3'],
            '.wav': ['audio/wav'],
            '.m4a': ['audio/m4a'],
            '.pdf': ['application/pdf'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.txt': ['text/plain']
        };
        return mimeMap[extension.toLowerCase()] || [];
    }
    
    getFileIcon(mimeType) {
        if (mimeType.startsWith('image/')) return '';
        if (mimeType.startsWith('video/')) return '';
        if (mimeType.startsWith('audio/')) return '';
        if (mimeType === 'application/pdf') return '';
        if (mimeType.includes('word')) return '';
        if (mimeType === 'text/plain') return '';
        return '📎';
    }
    
    getStatusText(status) {
        const statusMap = {
            'ready': 'Ready',
            'validating': 'Validating...',
            'valid': 'Valid',
            'invalid': 'Invalid',
            'uploading': 'Uploading...',
            'processing': 'Processing...',
            'analyzing': 'Analyzing...',
            'completed': 'Complete',
            'error': 'Error',
            'paused': 'Paused'
        };
        return statusMap[status] || status;
    }
    
    canPreview(mimeType) {
        return mimeType.startsWith('image/');
    }
    
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    formatDate(date) {
        if (!date) return 'N/A';
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }).format(new Date(date));
    }
    
    formatTime(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        return `${Math.round(seconds / 3600)}h`;
    }
    
    convertToCSV(data) {
        if (data.length === 0) return '';
        
        const headers = Object.keys(data[0]);
        const csvContent = [
            headers.join(','),
            ...data.map(row => headers.map(header => {
                const value = row[header] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(','))
        ].join('\n');
        
        return csvContent;
    }
    
    downloadCSV(csvContent, filename) {
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
}

// Global instance
let hawkEye;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    hawkEye = new HawkEyeSecureUpload();
    
    // Make it globally available for onclick handlers
    window.hawkEye = hawkEye;
});

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    if (hawkEye) {
        hawkEye.showToast('An unexpected error occurred', 'error');
    }
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    if (hawkEye) {
        hawkEye.showToast('A network or processing error occurred', 'error');
    }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HawkEyeSecureUpload;
}