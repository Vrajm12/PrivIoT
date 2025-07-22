// scan.js - Handles scan initiation, progress, and result visualization

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Add event listener to scan form submit
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            // Don't prevent default form submission - let server handle it
            // But show loading UI
            showScanProgress();
        });
    }

    // Initialize any scan result charts
    initializeScanCharts();
    
    // If scan is in progress, show progress UI
    const scanStatus = document.getElementById('scanStatus');
    if (scanStatus && scanStatus.dataset.status === 'running') {
        showScanProgress();
        
        // In a real app, you would poll the server for updates
        // For demo purposes, we'll simulate completion after 5 seconds
        setTimeout(function() {
            window.location.reload();
        }, 5000);
    }
    
    // Add click handlers for vulnerability and privacy issue accordions
    setupAccordionHandlers();
    
    // Setup report generation form
    setupReportForm();
});

/**
 * Shows the scan progress UI
 */
function showScanProgress() {
    const scanButton = document.getElementById('startScanBtn');
    const scanProgress = document.getElementById('scanProgress');
    
    if (scanButton) {
        scanButton.disabled = true;
        scanButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
    }
    
    if (scanProgress) {
        scanProgress.classList.remove('d-none');
        
        // Simulate progress updates
        let progress = 0;
        const progressBar = scanProgress.querySelector('.progress-bar');
        
        const interval = setInterval(function() {
            progress += 5;
            progressBar.style.width = progress + '%';
            progressBar.setAttribute('aria-valuenow', progress);
            
            if (progress >= 100) {
                clearInterval(interval);
                
                // In a real app, you would check the server for scan completion
                // For this demo, we'll add a small delay then reload
                setTimeout(function() {
                    scanButton.innerHTML = 'Scan Complete!';
                    window.location.reload();
                }, 500);
            }
        }, 500);
    }
}

/**
 * Initializes charts for scan results
 */
function initializeScanCharts() {
    // Render security score chart if element exists
    const securityScoreCanvas = document.getElementById('securityScoreChart');
    if (securityScoreCanvas) {
        renderScoreGauge(securityScoreCanvas, 'security');
    }
    
    // Render privacy score chart if element exists
    const privacyScoreCanvas = document.getElementById('privacyScoreChart');
    if (privacyScoreCanvas) {
        renderScoreGauge(privacyScoreCanvas, 'privacy');
    }
    
    // Render vulnerability distribution chart if element exists
    const vulnDistCanvas = document.getElementById('vulnerabilityDistributionChart');
    if (vulnDistCanvas) {
        renderVulnerabilityDistribution(vulnDistCanvas);
    }
}

/**
 * Renders a score gauge chart
 * @param {HTMLElement} canvas - Canvas element
 * @param {string} type - Either 'security' or 'privacy'
 */
function renderScoreGauge(canvas, type) {
    const score = parseFloat(canvas.dataset.score) || 0;
    
    // Determine color based on score
    let color = '#35c975'; // Green for good scores
    if (score < 4.0) {
        color = '#ff3547'; // Red for critical
    } else if (score < 5.5) {
        color = '#ff9f1c'; // Orange for high risk
    } else if (score < 7.0) {
        color = '#ffcc00'; // Yellow for medium risk
    }
    
    new Chart(canvas, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 10 - score],
                backgroundColor: [color, '#2a2d38'],
                borderWidth: 0
            }]
        },
        options: {
            cutout: '75%',
            responsive: true,
            maintainAspectRatio: false,
            circumference: 180,
            rotation: 270,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        }
    });

    // Add score text in center
    const scoreText = document.createElement('div');
    scoreText.classList.add('security-score');
    scoreText.textContent = score.toFixed(1);
    canvas.parentNode.appendChild(scoreText);
}

/**
 * Renders vulnerability distribution pie chart
 * @param {HTMLElement} canvas - Canvas element
 */
function renderVulnerabilityDistribution(canvas) {
    // Try to get chart data from data attribute
    let vulnerabilities = {};
    try {
        vulnerabilities = JSON.parse(canvas.dataset.vulnerabilities || '{}');
    } catch (e) {
        // Use default data if parsing fails
        vulnerabilities = {
            critical: 2,
            high: 4,
            medium: 7,
            low: 5
        };
    }
    
    new Chart(canvas, {
        type: 'pie',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    vulnerabilities.critical || 0,
                    vulnerabilities.high || 0,
                    vulnerabilities.medium || 0,
                    vulnerabilities.low || 0
                ],
                backgroundColor: [
                    '#ff3547', // Critical - Red
                    '#ff9f1c', // High - Orange
                    '#ffcc00', // Medium - Yellow
                    '#4287f5'  // Low - Blue
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

/**
 * Sets up click handlers for vulnerability and privacy issue accordions
 */
function setupAccordionHandlers() {
    // Add click listeners to all vulnerability accordions
    const vulnAccordions = document.querySelectorAll('.vulnerability-item');
    vulnAccordions.forEach(accordion => {
        const vulnId = accordion.dataset.vulnId;
        const recommendationBtn = accordion.querySelector('.recommendation-btn');
        
        if (recommendationBtn) {
            recommendationBtn.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Toggle recommendation visibility
                const recommendationArea = accordion.querySelector('.recommendation-area');
                if (recommendationArea) {
                    recommendationArea.classList.toggle('d-none');
                    
                    // Toggle button text
                    if (recommendationArea.classList.contains('d-none')) {
                        recommendationBtn.textContent = 'Show Recommendation';
                    } else {
                        recommendationBtn.textContent = 'Hide Recommendation';
                    }
                }
            });
        }
    });
    
    // Same for privacy issues
    const privacyAccordions = document.querySelectorAll('.privacy-item');
    privacyAccordions.forEach(accordion => {
        const issueId = accordion.dataset.issueId;
        const recommendationBtn = accordion.querySelector('.recommendation-btn');
        
        if (recommendationBtn) {
            recommendationBtn.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Toggle recommendation visibility
                const recommendationArea = accordion.querySelector('.recommendation-area');
                if (recommendationArea) {
                    recommendationArea.classList.toggle('d-none');
                    
                    // Toggle button text
                    if (recommendationArea.classList.contains('d-none')) {
                        recommendationBtn.textContent = 'Show Recommendation';
                    } else {
                        recommendationBtn.textContent = 'Hide Recommendation';
                    }
                }
            });
        }
    });
}

/**
 * Setup report generation form handlers
 */
function setupReportForm() {
    const reportForm = document.getElementById('generateReportForm');
    if (reportForm) {
        reportForm.addEventListener('submit', function(e) {
            // Don't prevent default - let server handle the form
            // But show loading state
            const submitBtn = reportForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';
            }
        });
    }
}
