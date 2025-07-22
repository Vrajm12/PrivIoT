// Dashboard.js - Handles dashboard UI interactions and chart rendering

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Render security score chart if the element exists
    const securityScoreCtx = document.getElementById('securityScoreChart');
    if (securityScoreCtx) {
        renderSecurityScoreChart(securityScoreCtx);
    }

    // Render vulnerability trend chart if the element exists
    const vulnerabilityTrendCtx = document.getElementById('vulnerabilityTrendChart');
    if (vulnerabilityTrendCtx) {
        renderVulnerabilityTrendChart(vulnerabilityTrendCtx);
    }

    // Render device security chart if the element exists
    const deviceSecurityCtx = document.getElementById('deviceSecurityChart');
    if (deviceSecurityCtx) {
        renderDeviceSecurityChart(deviceSecurityCtx);
    }

    // Render privacy score chart if the element exists
    const privacyScoreCtx = document.getElementById('privacyScoreChart');
    if (privacyScoreCtx) {
        renderPrivacyScoreChart(privacyScoreCtx);
    }
});

/**
 * Renders the security score gauge chart
 * @param {HTMLElement} ctx - Canvas element
 */
function renderSecurityScoreChart(ctx) {
    // Get the score value from the data attribute
    const scoreValue = parseFloat(ctx.dataset.score) || 0;
    
    // Determine color based on score
    let color = '#34C759'; // iOS green
    if (scoreValue < 4.0) {
        color = '#FF3B30'; // iOS red
    } else if (scoreValue < 5.5) {
        color = '#FF9500'; // iOS orange
    } else if (scoreValue < 7.0) {
        color = '#FFCC00'; // iOS yellow
    }
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [scoreValue, 10 - scoreValue],
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
    const scoreText = document.createElement('div');
    scoreText.classList.add('security-score');
    scoreText.textContent = scoreValue.toFixed(1);
    ctx.parentNode.appendChild(scoreText);
}

/**
 * Renders the vulnerability trend line chart
 * @param {HTMLElement} ctx - Canvas element
 */
function renderVulnerabilityTrendChart(ctx) {
    // Get trend data from data attribute (or use sample data)
    let trendData;
    try {
        trendData = JSON.parse(ctx.dataset.trend || '[]');
    } catch (e) {
        // Use sample data if parsing fails
        trendData = [
            { date: '2023-01-01', critical: 2, high: 5, medium: 8, low: 12 },
            { date: '2023-02-01', critical: 3, high: 4, medium: 7, low: 10 },
            { date: '2023-03-01', critical: 1, high: 3, medium: 6, low: 11 },
            { date: '2023-04-01', critical: 0, high: 4, medium: 5, low: 9 },
            { date: '2023-05-01', critical: 1, high: 2, medium: 4, low: 8 },
            { date: '2023-06-01', critical: 0, high: 1, medium: 3, low: 7 }
        ];
    }
    
    // Format data for chart
    const labels = trendData.map(item => {
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
                    data: trendData.map(item => item.critical),
                    borderColor: '#FF3B30', // iOS red
                    backgroundColor: 'rgba(255, 59, 48, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: trendData.map(item => item.high),
                    borderColor: '#FF9500', // iOS orange
                    backgroundColor: 'rgba(255, 149, 0, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: trendData.map(item => item.medium),
                    borderColor: '#FFCC00', // iOS yellow
                    backgroundColor: 'rgba(255, 204, 0, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Low',
                    data: trendData.map(item => item.low),
                    borderColor: '#007AFF', // iOS blue
                    backgroundColor: 'rgba(0, 122, 255, 0.1)',
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
 * Renders the device security horizontal bar chart
 * @param {HTMLElement} ctx - Canvas element
 */
function renderDeviceSecurityChart(ctx) {
    // Get device data from data attribute (or use sample data)
    let deviceData;
    try {
        deviceData = JSON.parse(ctx.dataset.devices || '[]');
    } catch (e) {
        // Use sample data if parsing fails
        deviceData = [
            { name: 'Smart Camera', score: 8.5 },
            { name: 'Smart Speaker', score: 7.2 },
            { name: 'Smart Thermostat', score: 6.5 },
            { name: 'Smart Lock', score: 5.8 },
            { name: 'Smart TV', score: 4.3 }
        ];
    }
    
    // Limit to 5 devices for better display
    if (deviceData.length > 5) {
        deviceData = deviceData.slice(0, 5);
    }
    
    // Sort devices by score (ascending)
    deviceData.sort((a, b) => a.score - b.score);
    
    // Create color array based on scores
    const colors = deviceData.map(device => {
        if (device.score < 4.0) return '#FF3B30'; // iOS red
        if (device.score < 5.5) return '#FF9500'; // iOS orange
        if (device.score < 7.0) return '#FFCC00'; // iOS yellow
        return '#34C759'; // iOS green
    });
    
    // If Chart.js has a getChart method, use it to check for existing chart
    if (Chart.getChart && Chart.getChart(ctx)) {
        Chart.getChart(ctx).destroy();
    }
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: deviceData.map(device => device.name.length > 15 ? device.name.substring(0, 15) + '...' : device.name),
            datasets: [{
                label: 'Security Score',
                data: deviceData.map(device => device.score),
                backgroundColor: colors,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            layout: {
                padding: {
                    left: 10,
                    right: 15,
                    top: 0,
                    bottom: 0
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 10,
                    grid: {
                        color: 'rgba(200, 200, 200, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(200, 200, 200, 0.7)'
                    }
                },
                y: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: 'rgba(200, 200, 200, 0.7)',
                        font: {
                            size: 11
                        }
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: function(tooltipItems) {
                            return deviceData[tooltipItems[0].dataIndex].name;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Renders the privacy score gauge chart
 * @param {HTMLElement} ctx - Canvas element
 */
function renderPrivacyScoreChart(ctx) {
    // Get the score value from the data attribute
    const scoreValue = parseFloat(ctx.dataset.score) || 0;
    
    // Determine color based on score
    let color = '#34C759'; // iOS green
    if (scoreValue < 4.0) {
        color = '#FF3B30'; // iOS red
    } else if (scoreValue < 5.5) {
        color = '#FF9500'; // iOS orange
    } else if (scoreValue < 7.0) {
        color = '#FFCC00'; // iOS yellow
    }
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [scoreValue, 10 - scoreValue],
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
    const scoreText = document.createElement('div');
    scoreText.classList.add('security-score');
    scoreText.textContent = scoreValue.toFixed(1);
    ctx.parentNode.appendChild(scoreText);
}
