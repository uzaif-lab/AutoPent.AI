// AutoPent.AI Frontend Application
class AutoPentApp {
    constructor() {
        this.currentScan = null;
        this.scanResults = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadRecentScans();
        this.checkApiHealth();
        this.loadConfig();
    }

    bindEvents() {
        // Tab navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const tab = e.currentTarget.dataset.tab;
                this.switchTab(tab);
            });
        });

        // Scan form submission
        document.getElementById('scanForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });
    }

    switchTab(tabName) {
        // Update nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');

        // Load tab-specific content
        if (tabName === 'reports') {
            this.loadRecentScans();
        }
    }

    async checkApiHealth() {
        try {
            const response = await fetch('/api/health');
            const data = await response.json();
            console.log('API Health:', data);
        } catch (error) {
            console.error('API health check failed:', error);
        }
    }

    async startScan() {
        const targetUrl = document.getElementById('targetUrl').value;
        const includeAI = document.getElementById('includeAI').checked;

        if (!targetUrl) {
            this.showError('Please enter a target URL');
            return;
        }

        try {
            // Show progress
            this.showScanProgress();
            this.updateProgress(0, 'Initializing scan...');

            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target_url: targetUrl,
                    include_ai: includeAI
                })
            });

            if (!response.ok) {
                // Get raw response text for debugging
                const errorText = await response.text();
                console.error('API Error Response:', errorText);
                
                try {
                    const errorData = JSON.parse(errorText);
                    throw new Error(errorData.error || 'Scan failed');
                } catch (parseError) {
                    // If it's not JSON, show the raw error
                    throw new Error(`Server Error (${response.status}): ${errorText.substring(0, 200)}...`);
                }
            }

            // Start progress monitoring
            this.monitorScanProgress();

            const scanData = await response.json();
            this.currentScan = scanData;
            this.scanResults = scanData.results;

            // Hide progress and show results
            this.hideScanProgress();
            this.displayResults(scanData);
            this.switchTab('results');

        } catch (error) {
            this.hideScanProgress();
            this.showError(`Scan failed: ${error.message}`);
        }
    }

    showScanProgress() {
        document.getElementById('scanProgress').classList.remove('hidden');
        document.querySelector('.scanner-form').style.opacity = '0.5';
        document.getElementById('startScanBtn').disabled = true;
    }

    hideScanProgress() {
        document.getElementById('scanProgress').classList.add('hidden');
        document.querySelector('.scanner-form').style.opacity = '1';
        document.getElementById('startScanBtn').disabled = false;
    }

    updateProgress(percent, text) {
        document.getElementById('progressFill').style.width = `${percent}%`;
        document.getElementById('progressText').textContent = text;

        // Update step indicators
        const steps = document.querySelectorAll('.step');
        steps.forEach((step, index) => {
            if (percent >= (index + 1) * 25) {
                step.classList.add('active');
            } else {
                step.classList.remove('active');
            }
        });
    }

    displayResults(scanData) {
        const results = scanData.results;
        const stats = results.statistics || {};
        const riskDist = stats.risk_distribution || {};

        // Hide no results message
        document.getElementById('noResults').classList.add('hidden');
        document.getElementById('resultsContent').classList.remove('hidden');

        // Update metrics
        document.getElementById('highRiskCount').textContent = riskDist.High || 0;
        document.getElementById('mediumRiskCount').textContent = riskDist.Medium || 0;
        document.getElementById('lowRiskCount').textContent = riskDist.Low || 0;
        document.getElementById('infoCount').textContent = riskDist.Informational || 0;

        // Display vulnerabilities table
        this.displayVulnerabilities(results.alerts || []);

        // Update reports section
        this.updateReportsSection(scanData);
    }

    displayVulnerabilities(vulnerabilities) {
        const tbody = document.getElementById('vulnerabilitiesBody');
        tbody.innerHTML = '';

        vulnerabilities.forEach(vuln => {
            const row = document.createElement('tr');
            
            const riskClass = this.getRiskClass(vuln.risk);
            const category = this.categorizeVulnerability(vuln.name);
            
            row.innerHTML = `
                <td>
                    <strong>${vuln.name}</strong>
                    <br>
                    <small style="color: #666;">${vuln.description?.substring(0, 100) || 'No description'}...</small>
                </td>
                <td>
                    <span class="risk-badge ${riskClass}">${vuln.risk}</span>
                </td>
                <td>${category}</td>
                <td>${vuln.confidence}</td>
            `;
            
            tbody.appendChild(row);
        });
    }

    getRiskClass(risk) {
        const riskMap = {
            'High': 'risk-high',
            'Medium': 'risk-medium',
            'Low': 'risk-low',
            'Informational': 'risk-info'
        };
        return riskMap[risk] || 'risk-info';
    }

    categorizeVulnerability(name) {
        const lowerName = name.toLowerCase();
        
        if (lowerName.includes('header')) return 'Security Headers';
        if (lowerName.includes('ssl') || lowerName.includes('certificate')) return 'SSL/TLS';
        if (lowerName.includes('javascript') || lowerName.includes('script')) return 'Content Security';
        if (lowerName.includes('admin') || lowerName.includes('path')) return 'Access Control';
        if (lowerName.includes('csrf') || lowerName.includes('form')) return 'Authentication';
        
        return 'Other';
    }

    updateReportsSection(scanData) {
        // Show reports content
        document.getElementById('noReports').classList.add('hidden');
        document.getElementById('reportsContent').classList.remove('hidden');

        // Update latest report card
        const latestReport = document.getElementById('latestReport');
        const stats = scanData.results.statistics || {};
        const total = stats.total_vulnerabilities || 0;
        const high = stats.risk_distribution?.High || 0;

        latestReport.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <div>
                    <h4>${scanData.target_url}</h4>
                    <p style="color: #666; margin: 0;">${new Date().toLocaleDateString()}</p>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #333;">${total}</div>
                    <div style="color: #666; font-size: 0.9rem;">Total Issues</div>
                </div>
            </div>
            <div style="display: flex; gap: 1rem; margin-bottom: 1rem;">
                <div class="risk-badge risk-high">High: ${stats.risk_distribution?.High || 0}</div>
                <div class="risk-badge risk-medium">Medium: ${stats.risk_distribution?.Medium || 0}</div>
                <div class="risk-badge risk-low">Low: ${stats.risk_distribution?.Low || 0}</div>
            </div>
            ${scanData.report_path ? `
                <button onclick="window.app.downloadReport('${scanData.scan_id}')" 
                        class="btn-primary" style="width: auto; margin-top: 1rem;">
                    <i class="fas fa-download"></i> Download PDF Report
                </button>
            ` : '<p style="color: #666;">Report generation in progress...</p>'}
        `;
    }

    async downloadReport(scanId) {
        try {
            const response = await fetch(`/api/download-report/${scanId}`);
            
            if (!response.ok) {
                throw new Error('Report not found');
            }

            // Create download link
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report-${scanId}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

        } catch (error) {
            this.showError(`Download failed: ${error.message}`);
        }
    }

    async loadRecentScans() {
        try {
            const response = await fetch('/api/recent-scans');
            const data = await response.json();
            
            this.displayRecentScans(data.scans || []);
        } catch (error) {
            console.error('Failed to load recent scans:', error);
        }
    }

    displayRecentScans(scans) {
        const scansList = document.getElementById('recentScansList');
        
        if (!scans.length) {
            scansList.innerHTML = '<p style="color: #666; text-align: center;">No recent scans available</p>';
            return;
        }

        scansList.innerHTML = scans.map(scan => `
            <div class="scan-item">
                <div>
                    <div style="font-weight: 500;">${scan.target_url}</div>
                    <div style="color: #666; font-size: 0.9rem;">${scan.timestamp}</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-weight: bold; color: #333;">${scan.findings_count}</div>
                    <div style="color: #666; font-size: 0.8rem;">findings</div>
                </div>
            </div>
        `).join('');
    }

    showError(message) {
        // Create error toast
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #f44336;
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 1000;
            max-width: 400px;
            animation: slideIn 0.3s ease;
        `;
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-exclamation-triangle"></i>
                <span>${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" 
                        style="background: none; border: none; color: white; cursor: pointer; margin-left: auto;">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        document.body.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async monitorScanProgress() {
        // Phase 1: Security Scan (0-40%)
        this.updateProgress(10, 'Initializing security scan...');
        await this.sleep(800);
        
        this.updateProgress(20, 'Analyzing HTTP headers...');
        await this.sleep(600);
        
        this.updateProgress(30, 'Checking SSL/TLS configuration...');
        await this.sleep(700);
        
        this.updateProgress(40, 'Scanning for vulnerabilities...');
        await this.sleep(1000);
        
        // Phase 2: AI Analysis (40-80%)
        const includeAI = document.getElementById('includeAI').checked;
        if (includeAI) {
            this.updateProgress(50, 'Starting AI analysis...');
            await this.sleep(800);
            
            this.updateProgress(60, 'Analyzing vulnerability risks...');
            await this.sleep(1200);
            
            this.updateProgress(70, 'Generating fix recommendations...');
            await this.sleep(1000);
            
            this.updateProgress(80, 'Finalizing AI insights...');
            await this.sleep(800);
        } else {
            this.updateProgress(65, 'Processing scan results...');
            await this.sleep(1000);
        }
        
        // Phase 3: Report Generation (80-100%)
        this.updateProgress(85, 'Generating PDF report...');
        await this.sleep(600);
        
        this.updateProgress(95, 'Finalizing report...');
        await this.sleep(400);
        
        this.updateProgress(100, 'Scan completed!');
    }

    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            const config = await response.json();
            
            // Auto-enable AI analysis if OpenAI is configured
            const aiCheckbox = document.getElementById('includeAI');
            if (config.ai_enabled) {
                aiCheckbox.checked = true;
                aiCheckbox.disabled = false;
                console.log('🤖 AI analysis enabled - OpenAI integration active!');
                
                // Show AI status message
                const aiStatus = document.createElement('div');
                aiStatus.style.cssText = 'margin-top: 10px; padding: 8px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; color: #155724; font-size: 12px;';
                aiStatus.innerHTML = '🤖 AI analysis is ready! Reports will include detailed risk analysis and fix recommendations.';
                aiCheckbox.parentNode.appendChild(aiStatus);
            } else {
                aiCheckbox.checked = false;
                aiCheckbox.disabled = true;
                console.log('💡 Add OPENAI_API_KEY to .env file to enable AI analysis');
            }
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    showSuccess(message) {
        // Implementation of showSuccess method
    }

    showInfo(message) {
        // Implementation of showInfo method
    }
}

// Add slide in animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
`;
document.head.appendChild(style);

// Initialize the application
window.app = new AutoPentApp(); 