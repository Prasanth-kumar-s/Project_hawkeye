// HawkEye 2.0 - AI-Based Deepfake & Social Engineering Detector
// JavaScript Application Logic

class HawkEyeApp {
    constructor() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.currentSection = 'dashboard';
        this.uploadedFiles = [];
        this.analysisResults = [];
        
        // Sample data from the provided JSON
        this.sampleThreats = [
            {
                id: "THR001",
                type: "Deepfake Video",
                source: "social_media.mp4",
                riskLevel: "High",
                confidence: 89.4,
                detectedAt: "2025-09-01T15:30:00Z",
                status: "Confirmed Threat",
                location: "Mumbai, India"
            },
            {
                id: "THR002", 
                type: "Phishing Email",
                source: "suspicious_email.eml",
                riskLevel: "Critical",
                confidence: 96.7,
                detectedAt: "2025-09-01T14:45:00Z",
                status: "Blocked",
                location: "Delhi, India"
            },
            {
                id: "THR003",
                type: "Manipulated Image",
                source: "fake_document.jpg", 
                riskLevel: "Medium",
                confidence: 72.3,
                detectedAt: "2025-09-01T13:20:00Z",
                status: "Under Review",
                location: "Bangalore, India"
            }
        ];
        
        this.dashboardMetrics = {
            totalScans: 15847,
            threatsDetected: 892,
            falsePositives: 45,
            systemUptime: "99.8%",
            avgProcessingTime: "2.4s",
            dailyScans: 1247
        };
        
        this.threatTrends = [
            {"date": "2025-08-25", "deepfakes": 12, "phishing": 25, "manipulated": 8},
            {"date": "2025-08-26", "deepfakes": 18, "phishing": 31, "manipulated": 12},
            {"date": "2025-08-27", "deepfakes": 15, "phishing": 28, "manipulated": 15},
            {"date": "2025-08-28", "deepfakes": 22, "phishing": 35, "manipulated": 18},
            {"date": "2025-08-29", "deepfakes": 19, "phishing": 40, "manipulated": 14},
            {"date": "2025-08-30", "deepfakes": 25, "phishing": 38, "manipulated": 22},
            {"date": "2025-09-01", "deepfakes": 28, "phishing": 42, "manipulated": 25}
        ];
        
        this.userActivity = [
            {"action": "File Upload", "user": "analyst@hawkeye.ai", "timestamp": "2025-09-01T15:45:00Z", "details": "Uploaded suspicious_video.mp4"},
            {"action": "Threat Confirmed", "user": "admin@hawkeye.ai", "timestamp": "2025-09-01T15:30:00Z", "details": "Confirmed deepfake detection THR001"},
            {"action": "Report Generated", "user": "security@hawkeye.ai", "timestamp": "2025-09-01T14:20:00Z", "details": "Weekly threat report exported"},
            {"action": "URL Analyzed", "user": "researcher@hawkeye.ai", "timestamp": "2025-09-01T13:15:00Z", "details": "Analyzed phishing URL"}
        ];
        
        this.detectionModels = [
            {
                name: "DeepFake Video Detector v2.1",
                accuracy: "94.2%",
                lastUpdated: "2025-08-28",
                status: "Active"
            },
            {
                name: "Phishing Email Analyzer v1.8", 
                accuracy: "96.7%",
                lastUpdated: "2025-08-30",
                status: "Active"
            },
            {
                name: "Image Manipulation Detector v3.0",
                accuracy: "91.5%", 
                lastUpdated: "2025-08-29",
                status: "Active"
            },
            {
                name: "Audio Deepfake Detector v1.5",
                accuracy: "88.9%",
                lastUpdated: "2025-08-27", 
                status: "Active"
            }
        ];
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.checkAuthStatus();
    }
    
    setupEventListeners() {
        // Authentication
        document.getElementById('loginForm').addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('otpLogin').addEventListener('click', () => this.handleOTPLogin());
        document.getElementById('logoutBtn').addEventListener('click', () => this.handleLogout());
        
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => this.handleNavigation(e));
        });
        
        // File Upload
        this.setupFileUpload();
        
        // URL Analysis
        document.getElementById('analyzeUrl').addEventListener('click', () => this.analyzeURL());
        
        // Email Analysis
        document.getElementById('analyzeEmail').addEventListener('click', () => this.analyzeEmail());
        
        // Results Filtering
        document.getElementById('riskFilter').addEventListener('change', () => this.filterResults());
        document.getElementById('typeFilter').addEventListener('change', () => this.filterResults());
        document.getElementById('exportResults').addEventListener('click', () => this.exportResults());
        
        // Modal Controls
        document.querySelectorAll('.modal-close').forEach(close => {
            close.addEventListener('click', () => this.closeModal());
        });
        
        // Report Generation
        document.querySelectorAll('.report-card .btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.generateReport(e.target.closest('.report-card')));
        });
        
        // Click outside modal to close
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModal();
            }
        });
    }
    
    checkAuthStatus() {
        // Simulate authentication check
        const loginModal = document.getElementById('loginModal');
        const app = document.getElementById('app');
        
        if (this.isAuthenticated) {
            loginModal.classList.add('hidden');
            app.classList.remove('hidden');
            this.loadDashboard();
        } else {
            loginModal.classList.remove('hidden');
            app.classList.add('hidden');
        }
    }
    
    handleLogin(e) {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        if (email && password) {
            // Simulate authentication
            this.isAuthenticated = true;
            this.currentUser = {
                email: email,
                name: 'Security Analyst',
                role: email.includes('admin') ? 'Admin' : 'Analyst'
            };
            
            this.showToast('Login successful', 'success');
            this.checkAuthStatus();
        } else {
            this.showToast('Please enter valid credentials', 'error');
        }
    }
    
    handleOTPLogin() {
        // Simulate OTP login
        const email = document.getElementById('email').value;
        if (email) {
            this.showToast('OTP sent to your email', 'success');
            setTimeout(() => {
                this.isAuthenticated = true;
                this.currentUser = {
                    email: email,
                    name: 'Security Analyst',
                    role: 'Analyst'
                };
                this.checkAuthStatus();
            }, 2000);
        } else {
            this.showToast('Please enter your email address', 'error');
        }
    }
    
    handleLogout() {
        this.isAuthenticated = false;
        this.currentUser = null;
        this.showToast('Logged out successfully', 'success');
        this.checkAuthStatus();
    }
    
    handleNavigation(e) {
        e.preventDefault();
        const section = e.target.closest('.nav-link').dataset.section;
        
        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
        e.target.closest('.nav-link').classList.add('active');
        
        // Show/hide sections
        document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
        document.getElementById(`${section}-section`).classList.add('active');
        
        this.currentSection = section;
        
        // Load section-specific data
        switch(section) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'results':
                this.loadResults();
                break;
            case 'admin':
                this.loadAdminPanel();
                break;
        }
    }
    
    loadDashboard() {
        // Update metrics
        document.getElementById('totalScans').textContent = this.dashboardMetrics.totalScans.toLocaleString();
        document.getElementById('threatsDetected').textContent = this.dashboardMetrics.threatsDetected.toLocaleString();
        document.getElementById('systemUptime').textContent = this.dashboardMetrics.systemUptime;
        document.getElementById('avgProcessingTime').textContent = this.dashboardMetrics.avgProcessingTime;
        
        // Load threat feed
        this.loadThreatFeed();
        
        // Load recent activity
        this.loadRecentActivity();
        
        // Create charts
        setTimeout(() => this.createThreatTrendsChart(), 100);
        
        // Load map data
        this.loadThreatMap();
    }
    
    loadThreatFeed() {
        const threatFeed = document.getElementById('threatFeed');
        threatFeed.innerHTML = '';
        
        this.sampleThreats.forEach(threat => {
            const threatItem = document.createElement('div');
            threatItem.className = `threat-item ${threat.riskLevel.toLowerCase()}`;
            threatItem.innerHTML = `
                <div class="threat-item-header">
                    <span class="threat-type">${threat.type}</span>
                    <span class="threat-time">${this.formatTime(threat.detectedAt)}</span>
                </div>
                <div class="threat-source">${threat.source}</div>
            `;
            threatFeed.appendChild(threatItem);
        });
    }
    
    loadRecentActivity() {
        const activityList = document.getElementById('recentActivity');
        activityList.innerHTML = '';
        
        this.userActivity.forEach(activity => {
            const activityItem = document.createElement('div');
            activityItem.className = 'activity-item';
            activityItem.innerHTML = `
                <div class="activity-icon">ðŸ“‹</div>
                <div class="activity-details">
                    <div class="activity-action">${activity.action}</div>
                    <div class="activity-meta">${activity.user} â€¢ ${this.formatTime(activity.timestamp)}</div>
                </div>
            `;
            activityList.appendChild(activityItem);
        });
    }
    
    createThreatTrendsChart() {
        const ctx = document.getElementById('threatTrendsChart');
        if (!ctx) return;
        
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.threatTrends.map(item => item.date.split('-').slice(1).join('/')),
                datasets: [
                    {
                        label: 'Deepfakes',
                        data: this.threatTrends.map(item => item.deepfakes),
                        borderColor: '#1FB8CD',
                        backgroundColor: 'rgba(31, 184, 205, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Phishing',
                        data: this.threatTrends.map(item => item.phishing),
                        borderColor: '#FFC185',
                        backgroundColor: 'rgba(255, 193, 133, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Manipulated Media',
                        data: this.threatTrends.map(item => item.manipulated),
                        borderColor: '#B4413C',
                        backgroundColor: 'rgba(180, 65, 60, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    loadThreatMap() {
        const threatMap = document.getElementById('threatMap');
        if (!threatMap) return;
        
        threatMap.innerHTML = '<p>Interactive threat map showing geographic distribution</p>';
        
        // Simulate map points
        const cities = [
            {name: 'Mumbai', threats: 145, x: 30, y: 60},
            {name: 'Delhi', threats: 132, x: 25, y: 20},
            {name: 'Bangalore', threats: 98, x: 35, y: 80},
            {name: 'Chennai', threats: 87, x: 45, y: 85},
            {name: 'Hyderabad', threats: 76, x: 40, y: 70}
        ];
        
        cities.forEach(city => {
            const point = document.createElement('div');
            point.className = 'map-point';
            point.style.left = `${city.x}%`;
            point.style.top = `${city.y}%`;
            point.title = `${city.name}: ${city.threats} threats`;
            threatMap.appendChild(point);
        });
    }
    
    setupFileUpload() {
        const uploadArea = document.getElementById('fileUploadArea');
        const fileInput = document.getElementById('fileInput');
        
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = Array.from(e.dataTransfer.files);
            this.handleFileUpload(files);
        });
        
        fileInput.addEventListener('change', (e) => {
            const files = Array.from(e.target.files);
            this.handleFileUpload(files);
        });
    }
    
    handleFileUpload(files) {
        files.forEach(file => {
            if (this.validateFile(file)) {
                this.uploadFile(file);
            }
        });
    }
    
    validateFile(file) {
        const allowedTypes = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
            'video/mp4', 'video/avi', 'video/mov',
            'audio/mp3', 'audio/wav', 'audio/m4a',
            'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        
        const maxSizes = {
            'video': 50 * 1024 * 1024, // 50MB
            'image': 10 * 1024 * 1024, // 10MB
            'audio': 10 * 1024 * 1024, // 10MB
            'application': 5 * 1024 * 1024 // 5MB
        };
        
        const fileType = file.type.split('/')[0];
        const maxSize = maxSizes[fileType] || maxSizes['application'];
        
        if (!allowedTypes.includes(file.type)) {
            this.showToast(`File type ${file.type} not supported`, 'error');
            return false;
        }
        
        if (file.size > maxSize) {
            this.showToast(`File size exceeds limit (${Math.round(maxSize / 1024 / 1024)}MB)`, 'error');
            return false;
        }
        
        return true;
    }
    
    uploadFile(file) {
        const progressContainer = document.getElementById('fileProgress');
        const progressFill = progressContainer.querySelector('.progress-fill');
        const progressText = progressContainer.querySelector('.progress-text');
        
        progressContainer.classList.remove('hidden');
        
        // Simulate upload progress
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                progressText.textContent = 'Upload complete';
                
                // Start analysis
                setTimeout(() => {
                    this.startAnalysis(file);
                }, 1000);
            }
            
            progressFill.style.width = `${progress}%`;
            progressText.textContent = `Uploading ${file.name}... ${Math.round(progress)}%`;
        }, 200);
    }
    
    startAnalysis(file) {
        const modal = document.getElementById('analysisModal');
        const statusText = document.getElementById('analysisStatus');
        const steps = modal.querySelectorAll('.step');
        
        modal.classList.remove('hidden');
        
        const analysisSteps = [
            'File validation complete',
            'Virus scan passed',
            'AI analysis in progress',
            'Generating results'
        ];
        
        let currentStep = 0;
        
        const stepInterval = setInterval(() => {
            if (currentStep > 0) {
                steps[currentStep - 1].classList.remove('active');
                steps[currentStep - 1].classList.add('complete');
            }
            
            if (currentStep < steps.length) {
                steps[currentStep].classList.add('active');
                statusText.textContent = analysisSteps[currentStep];
                currentStep++;
            } else {
                clearInterval(stepInterval);
                
                // Generate analysis result
                const result = this.generateAnalysisResult(file);
                this.analysisResults.unshift(result);
                
                setTimeout(() => {
                    modal.classList.add('hidden');
                    this.showAnalysisResult(result);
                    this.showToast('Analysis complete', 'success');
                    
                    // Reset progress
                    document.getElementById('fileProgress').classList.add('hidden');
                    document.getElementById('fileInput').value = '';
                }, 1000);
            }
        }, 1500);
    }
    
    generateAnalysisResult(file) {
        const riskLevels = ['Low', 'Medium', 'High', 'Critical'];
        const threatTypes = ['Deepfake Video', 'Phishing Email', 'Manipulated Image', 'Audio Deepfake', 'Social Engineering'];
        
        return {
            id: `THR${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`,
            type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
            source: file.name,
            riskLevel: riskLevels[Math.floor(Math.random() * riskLevels.length)],
            confidence: Math.floor(Math.random() * 40) + 60,
            detectedAt: new Date().toISOString(),
            status: 'Analysis Complete',
            location: 'Local Upload',
            fileSize: this.formatFileSize(file.size),
            analysisTime: Math.floor(Math.random() * 5) + 2 + 's'
        };
    }
    
    analyzeURL() {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showToast('Please enter a URL to analyze', 'error');
            return;
        }
        
        if (!this.isValidURL(url)) {
            this.showToast('Please enter a valid URL', 'error');
            return;
        }
        
        this.showToast('Analyzing URL...', 'success');
        
        // Simulate URL analysis
        setTimeout(() => {
            const result = {
                id: `THR${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`,
                type: 'Phishing Website',
                source: url,
                riskLevel: Math.random() > 0.5 ? 'High' : 'Medium',
                confidence: Math.floor(Math.random() * 30) + 70,
                detectedAt: new Date().toISOString(),
                status: 'Analysis Complete',
                location: 'URL Analysis'
            };
            
            this.analysisResults.unshift(result);
            this.showAnalysisResult(result);
            urlInput.value = '';
        }, 2000);
    }
    
    analyzeEmail() {
        const emailContent = document.getElementById('emailContent').value.trim();
        
        if (!emailContent) {
            this.showToast('Please enter email content to analyze', 'error');
            return;
        }
        
        this.showToast('Analyzing email content...', 'success');
        
        // Simulate email analysis
        setTimeout(() => {
            const result = {
                id: `THR${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`,
                type: 'Phishing Email',
                source: 'Email Content',
                riskLevel: Math.random() > 0.3 ? 'Critical' : 'High',
                confidence: Math.floor(Math.random() * 25) + 75,
                detectedAt: new Date().toISOString(),
                status: 'Analysis Complete',
                location: 'Email Analysis'
            };
            
            this.analysisResults.unshift(result);
            this.showAnalysisResult(result);
            document.getElementById('emailContent').value = '';
        }, 2000);
    }
    
    showAnalysisResult(result) {
        const modal = document.getElementById('resultModal');
        const details = document.getElementById('resultDetails');
        
        details.innerHTML = `
            <div class="result-card">
                <div class="result-header">
                    <span class="result-id">${result.id}</span>
                    <span class="risk-badge ${result.riskLevel.toLowerCase()}">${result.riskLevel} Risk</span>
                </div>
                <div class="result-details">
                    <div class="result-detail">
                        <span class="result-label">Threat Type</span>
                        <span class="result-value">${result.type}</span>
                    </div>
                    <div class="result-detail">
                        <span class="result-label">Source</span>
                        <span class="result-value">${result.source}</span>
                    </div>
                    <div class="result-detail">
                        <span class="result-label">Confidence</span>
                        <span class="result-value">${result.confidence}%</span>
                    </div>
                    <div class="result-detail">
                        <span class="result-label">Status</span>
                        <span class="result-value">${result.status}</span>
                    </div>
                </div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${result.confidence}%"></div>
                </div>
            </div>
        `;
        
        modal.classList.remove('hidden');
    }
    
    loadResults() {
        const allResults = [...this.sampleThreats, ...this.analysisResults];
        this.displayResults(allResults);
    }
    
    displayResults(results) {
        const container = document.getElementById('resultsContainer');
        container.innerHTML = '';
        
        results.forEach(result => {
            const resultCard = document.createElement('div');
            resultCard.className = 'result-card';
            resultCard.innerHTML = `
                <div class="result-header">
                    <span class="result-id">${result.id}</span>
                    <span class="risk-badge ${result.riskLevel.toLowerCase()}">${result.riskLevel}</span>
                </div>
                <div class="result-details">
                    <div class="result-detail">
                        <span class="result-label">Type</span>
                        <span class="result-value">${result.type}</span>
                    </div>
                    <div class="result-detail">
                        <span class="result-label">Source</span>
                        <span class="result-value">${result.source}</span>
                    </div>
                    <div class="result-detail">
                        <span class="result-label">Confidence</span>
                        <span class="result-value">${result.confidence}%</span>
                    </div>
                    <div class="result-detail">
                        <span class="result-label">Status</span>
                        <span class="result-value">${result.status}</span>
                    </div>
                </div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${result.confidence}%"></div>
                </div>
            `;
            
            resultCard.addEventListener('click', () => this.showAnalysisResult(result));
            container.appendChild(resultCard);
        });
    }
    
    filterResults() {
        const riskFilter = document.getElementById('riskFilter').value;
        const typeFilter = document.getElementById('typeFilter').value;
        const allResults = [...this.sampleThreats, ...this.analysisResults];
        
        let filteredResults = allResults;
        
        if (riskFilter !== 'all') {
            filteredResults = filteredResults.filter(result => 
                result.riskLevel.toLowerCase() === riskFilter
            );
        }
        
        if (typeFilter !== 'all') {
            filteredResults = filteredResults.filter(result => 
                result.type.toLowerCase().includes(typeFilter)
            );
        }
        
        this.displayResults(filteredResults);
    }
    
    exportResults() {
        const results = [...this.sampleThreats, ...this.analysisResults];
        const csvContent = this.convertToCSV(results);
        this.downloadCSV(csvContent, 'hawkeye_analysis_results.csv');
        this.showToast('Results exported successfully', 'success');
    }
    
    loadAdminPanel() {
        this.loadDetectionModels();
    }
    
    loadDetectionModels() {
        const modelsContainer = document.getElementById('detectionModels');
        if (!modelsContainer) return;
        
        modelsContainer.innerHTML = '';
        
        this.detectionModels.forEach(model => {
            const modelItem = document.createElement('div');
            modelItem.className = 'model-item';
            modelItem.innerHTML = `
                <div class="model-header">
                    <span class="model-name">${model.name}</span>
                    <span class="model-status">${model.status}</span>
                </div>
                <div class="model-details">
                    <span>Accuracy: ${model.accuracy}</span>
                    <span>Updated: ${model.lastUpdated}</span>
                </div>
            `;
            modelsContainer.appendChild(modelItem);
        });
    }
    
    generateReport(reportCard) {
        const reportType = reportCard.querySelector('h3').textContent;
        this.showToast(`Generating ${reportType}...`, 'success');
        
        setTimeout(() => {
            this.showToast(`${reportType} generated successfully`, 'success');
        }, 2000);
    }
    
    closeModal() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.add('hidden');
        });
    }
    
    showToast(message, type = 'success') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }
    
    // Utility functions
    formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }
    
    formatFileSize(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }
    
    isValidURL(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    convertToCSV(data) {
        const headers = ['ID', 'Type', 'Source', 'Risk Level', 'Confidence', 'Status', 'Location', 'Detected At'];
        const csvRows = [headers.join(',')];
        
        data.forEach(row => {
            const values = [
                row.id,
                row.type,
                row.source,
                row.riskLevel,
                row.confidence,
                row.status,
                row.location,
                row.detectedAt
            ];
            csvRows.push(values.join(','));
        });
        
        return csvRows.join('\n');
    }
    
    downloadCSV(csvContent, filename) {
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.setAttribute('hidden', '');
        a.setAttribute('href', url);
        a.setAttribute('download', filename);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new HawkEyeApp();
});