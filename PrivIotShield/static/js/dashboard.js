// Dashboard.js - Modern dashboard UI interactions and chart rendering

// Global chart options
const chartOptions = {
    animations: {
        enabled: true,
        easing: 'easeOutQuart',
        duration: 1000,
        delay: 100
    },
    responsive: true,
    colors: {
        success: '#10B981',
        warning: '#F59E0B',
        medium: '#FBBF24',
        danger: '#EF4444',
        info: '#3B82F6',
        primary: '#6366F1',
        secondary: '#8B5CF6',
        background: 'rgba(30, 41, 59, 0.8)'
    }
};

document.addEventListener('DOMContentLoaded', function() {
    // Add fade-in animation to stat cards
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach((card, index) => {
        setTimeout(() => {
            card.classList.add('show');
        }, index * 100);
    });

    // Render security score chart if the element exists
    const securityScoreCtx = document.getElementById('securityScoreChart');
    if (securityScoreCtx) {
        renderSecurityScoreChart(securityScoreCtx);
    }

    // Render privacy score chart if the element exists
    const privacyScoreCtx = document.getElementById('privacyScoreChart');
    if (privacyScoreCtx) {
        renderPrivacyScoreChart(privacyScoreCtx);
    }

    // Render device security chart if the element exists
    const deviceSecurityCtx = document.getElementById('deviceSecurityChart');
    if (deviceSecurityCtx) {
        renderDeviceSecurityChart(deviceSecurityCtx);
    }

    // Render vulnerability distribution chart if the element exists
    const vulnerabilityDistCtx = document.getElementById('vulnerabilityDistributionChart');
    if (vulnerabilityDistCtx) {
        renderVulnerabilityDistributionChart(vulnerabilityDistCtx);
    }

    // Enable floating labels in forms
    const formFloatingInputs = document.querySelectorAll('.form-floating input, .form-floating textarea');
    formFloatingInputs.forEach(input => {
        if (input.value !== '') {
            input.parentElement.classList.add('filled');
        }
        input.addEventListener('focus', () => {
            input.parentElement.classList.add('focused');
        });
        input.addEventListener('blur', () => {
            input.parentElement.classList.remove('focused');
            if (input.value !== '') {
                input.parentElement.classList.add('filled');
            } else {
                input.parentElement.classList.remove('filled');
            }
        });
    });

    // Add smooth scrolling behavior
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            if (targetId !== '#' && document.querySelector(targetId)) {
                e.preventDefault();
                document.querySelector(targetId).scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
});

/**
 * Renders the security score gauge chart with gradient and animation
 * @param {HTMLElement} ctx - Canvas element
 */
function renderSecurityScoreChart(ctx) {
    // Get the score value from the data attribute
    const scoreValue = parseFloat(ctx.dataset.score) || 0;
    createScoreGauge(ctx.id, scoreValue, 'security');
}

/**
 * Renders the privacy score gauge chart with gradient and animation
 * @param {HTMLElement} ctx - Canvas element
 */
function renderPrivacyScoreChart(ctx) {
    // Get the score value from the data attribute
    const scoreValue = parseFloat(ctx.dataset.score) || 0;
    createScoreGauge(ctx.id, scoreValue, 'privacy');
}

/**
 * Renders the device security horizontal bar chart with modern styling
 * @param {HTMLElement} ctx - Canvas element
 */
function renderDeviceSecurityChart(ctx) {
    // Get device data from data attribute
    let deviceData;
    try {
        deviceData = JSON.parse(ctx.dataset.devices || '[]');
    } catch (e) {
        console.error('Error parsing device data:', e);
        deviceData = [];
    }
    
    // If data exists, render the chart
    if (deviceData && deviceData.length > 0) {
        // Limit to 5 devices for better display
        if (deviceData.length > 5) {
            deviceData = deviceData.slice(0, 5);
        }
        
        // If Chart.js has a getChart method, use it to check for existing chart
        if (Chart.getChart && Chart.getChart(ctx)) {
            Chart.getChart(ctx).destroy();
        }
        
        createDeviceComparisonChart(ctx.id, deviceData);
    }
}

/**
 * Renders the vulnerability distribution pie chart
 * @param {HTMLElement} ctx - Canvas element
 */
function renderVulnerabilityDistributionChart(ctx) {
    // Get vulnerability distribution data from data attribute
    let vulnData;
    try {
        vulnData = JSON.parse(ctx.dataset.distribution || '{}');
    } catch (e) {
        console.error('Error parsing vulnerability distribution data:', e);
        return;
    }
    
    // Create the chart
    createVulnerabilityDistribution(ctx.id, vulnData);
}

/**
 * Updates the dashboard UI theme based on user preference
 * @param {string} theme - Theme name ('light' or 'dark')
 */
function updateDashboardTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    // Find all charts and update them
    const chartElements = document.querySelectorAll('canvas');
    chartElements.forEach(canvas => {
        const chart = Chart.getChart(canvas);
        if (chart) {
            // Destroy and re-render the chart
            const canvasId = canvas.id;
            const parentElement = canvas.parentNode;
            
            // Temporarily store any data attributes
            const dataset = {};
            Object.keys(canvas.dataset).forEach(key => {
                dataset[key] = canvas.dataset[key];
            });
            
            // Destroy chart and recreate canvas
            chart.destroy();
            parentElement.innerHTML = '';
            const newCanvas = document.createElement('canvas');
            newCanvas.id = canvasId;
            
            // Restore data attributes
            Object.keys(dataset).forEach(key => {
                newCanvas.dataset[key] = dataset[key];
            });
            
            parentElement.appendChild(newCanvas);
            
            // Re-render chart based on type
            if (canvasId === 'securityScoreChart') {
                renderSecurityScoreChart(newCanvas);
            } else if (canvasId === 'privacyScoreChart') {
                renderPrivacyScoreChart(newCanvas);
            } else if (canvasId === 'deviceSecurityChart') {
                renderDeviceSecurityChart(newCanvas);
            } else if (canvasId === 'vulnerabilityDistributionChart') {
                renderVulnerabilityDistributionChart(newCanvas);
            }
        }
    });
}

// Event listener for theme toggle button
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            updateDashboardTheme(newTheme);
        });
    }
    
    // Apply saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
});
