// charts.js - Common charting functions for the application

/**
 * Creates a gauge chart for security/privacy scores
 * @param {string} elementId - Canvas element ID
 * @param {number} score - Score value (0-10)
 * @param {string} type - Type of score ('security' or 'privacy')
 */
function createScoreGauge(elementId, score, type) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    // Determine color based on score
    let color = '#35c975'; // Green for good scores
    if (score < 4.0) {
        color = '#ff3547'; // Red for critical
    } else if (score < 5.5) {
        color = '#ff9f1c'; // Orange for high risk
    } else if (score < 7.0) {
        color = '#ffcc00'; // Yellow for medium risk
    }
    
    new Chart(ctx, {
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

    // Add score text in the center
    const scoreContainer = ctx.parentNode;
    if (scoreContainer) {
        const scoreText = document.createElement('div');
        scoreText.classList.add('security-score');
        scoreText.textContent = score.toFixed(1);
        scoreContainer.appendChild(scoreText);
    }
}

/**
 * Creates a vulnerability distribution chart
 * @param {string} elementId - Canvas element ID
 * @param {Object} data - Vulnerability counts by severity
 */
function createVulnerabilityDistribution(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    // Extract data values
    const critical = data.critical || 0;
    const high = data.high || 0;
    const medium = data.medium || 0;
    const low = data.low || 0;
    
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [critical, high, medium, low],
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
 * Creates a trend line chart for vulnerabilities over time
 * @param {string} elementId - Canvas element ID
 * @param {Array} data - Array of data points with date and severity counts
 */
function createVulnerabilityTrend(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    // Extract labels (dates)
    const labels = data.map(item => {
        const date = new Date(item.date);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Critical',
                    data: data.map(item => item.critical),
                    borderColor: '#ff3547',
                    backgroundColor: 'rgba(255, 53, 71, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: data.map(item => item.high),
                    borderColor: '#ff9f1c',
                    backgroundColor: 'rgba(255, 159, 28, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: data.map(item => item.medium),
                    borderColor: '#ffcc00',
                    backgroundColor: 'rgba(255, 204, 0, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Low',
                    data: data.map(item => item.low),
                    borderColor: '#4287f5',
                    backgroundColor: 'rgba(66, 135, 245, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(200, 200, 200, 0.1)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

/**
 * Creates a horizontal bar chart for device security comparison
 * @param {string} elementId - Canvas element ID
 * @param {Array} data - Array of device objects with name and score
 */
function createDeviceComparisonChart(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    // Sort devices by score (ascending)
    data.sort((a, b) => a.score - b.score);
    
    // Create color array based on scores
    const colors = data.map(device => {
        if (device.score < 4.0) return '#ff3547'; // Red for critical
        if (device.score < 5.5) return '#ff9f1c'; // Orange for high risk
        if (device.score < 7.0) return '#ffcc00'; // Yellow for medium risk
        return '#35c975'; // Green for good scores
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(device => device.name),
            datasets: [{
                label: 'Security Score',
                data: data.map(device => device.score),
                backgroundColor: colors,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    max: 10,
                    grid: {
                        color: 'rgba(200, 200, 200, 0.1)'
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Initialize all tooltips on the page
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize all popovers on the page
 */
function initPopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Initialize tooltips and popovers when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();
    initPopovers();
});
