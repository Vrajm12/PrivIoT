// charts.js - Modern charting functions with gradient and animation effects

// Define color scheme for charts
const chartColors = {
    primary: '#6366F1',    // Indigo
    secondary: '#8B5CF6',  // Purple
    tertiary: '#EC4899',   // Pink
    success: '#10B981',    // Emerald
    danger: '#EF4444',     // Red
    warning: '#F59E0B',    // Amber
    info: '#3B82F6',       // Blue
    medium: '#FBBF24',     // Yellow
    low: '#38BDF8',        // Light blue
    background: 'rgba(30, 41, 59, 0.8)', // Dark slate
    gridLines: 'rgba(71, 85, 105, 0.1)'  // Subtle grid lines
};

// Light theme colors
const lightChartColors = {
    background: 'rgba(255, 255, 255, 0.8)',
    gridLines: 'rgba(203, 213, 225, 0.3)'
};

// Create gradient backgrounds for charts
function createGradient(ctx, startColor, endColor) {
    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, startColor);
    gradient.addColorStop(1, endColor);
    return gradient;
}

/**
 * Creates a modern gauge chart for security/privacy scores with animation
 * @param {string} elementId - Canvas element ID
 * @param {number} score - Score value (0-10)
 * @param {string} type - Type of score ('security' or 'privacy')
 */
function createScoreGauge(elementId, score, type) {
    const canvas = document.getElementById(elementId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Get theme
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    
    // Determine colors based on score
    let startColor, endColor;
    
    if (score < 4.0) {
        startColor = chartColors.danger;
        endColor = '#F87171'; // Lighter red
    } else if (score < 5.5) {
        startColor = chartColors.warning;
        endColor = '#FCD34D'; // Lighter amber
    } else if (score < 7.0) {
        startColor = chartColors.medium;
        endColor = '#FDE68A'; // Lighter yellow
    } else {
        startColor = chartColors.success;
        endColor = '#34D399'; // Lighter green
    }
    
    // Create gradient for score segment
    const scoreGradient = createGradient(ctx, startColor, endColor);
    
    // Background color based on theme
    const backgroundColor = theme === 'light' 
        ? 'rgba(226, 232, 240, 0.6)' 
        : 'rgba(30, 41, 59, 0.3)';
    
    // Animation options - simplified for compatibility
    const animation = {
        duration: 1000,
        easing: 'easeOutQuart'
    };
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 10 - score],
                backgroundColor: [scoreGradient, backgroundColor],
                borderWidth: 0,
                borderRadius: 5,
            }]
        },
        options: {
            cutout: '75%',
            responsive: true,
            maintainAspectRatio: false,
            circumference: 180,
            rotation: 270,
            animation: animation,
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
    const scoreContainer = canvas.parentNode;
    if (scoreContainer) {
        // Remove any existing score text first
        const existingScoreText = scoreContainer.querySelector('.security-score');
        if (existingScoreText) {
            existingScoreText.remove();
        }
        
        const scoreDiv = document.createElement('div');
        scoreDiv.classList.add('security-score');
        scoreDiv.textContent = score.toFixed(1);
        scoreContainer.appendChild(scoreDiv);
    }
}

/**
 * Creates a vulnerability distribution chart with gradient colors
 * @param {string} elementId - Canvas element ID
 * @param {Object} data - Vulnerability counts by severity
 */
function createVulnerabilityDistribution(elementId, data) {
    const canvas = document.getElementById(elementId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Extract data values
    const critical = data.critical || 0;
    const high = data.high || 0;
    const medium = data.medium || 0;
    const low = data.low || 0;
    
    // Create gradients
    const criticalGradient = createGradient(ctx, chartColors.danger, '#F87171');
    const highGradient = createGradient(ctx, chartColors.warning, '#FCD34D');
    const mediumGradient = createGradient(ctx, chartColors.medium, '#FDE68A');
    const lowGradient = createGradient(ctx, chartColors.info, '#7DD3FC');
    
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: [
                    criticalGradient, // Critical - Red gradient
                    highGradient,     // High - Orange gradient
                    mediumGradient,   // Medium - Yellow gradient
                    lowGradient       // Low - Blue gradient
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: {
                            family: "'Inter', sans-serif",
                            size: 12
                        }
                    }
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true,
                duration: 2000,
                easing: 'easeOutQuart'
            }
        }
    });
}

/**
 * Creates a modern trend line chart for vulnerabilities over time with gradients
 * @param {string} elementId - Canvas element ID
 * @param {Array} data - Array of data points with date and severity counts
 */
function createVulnerabilityTrend(elementId, data) {
    const canvas = document.getElementById(elementId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Get theme
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    
    // Extract labels (dates)
    const labels = data.map(item => {
        const date = new Date(item.date);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });
    
    // Create gradients
    const criticalGradient = createGradient(ctx, 'rgba(239, 68, 68, 0.8)', 'rgba(239, 68, 68, 0.1)');
    const highGradient = createGradient(ctx, 'rgba(245, 158, 11, 0.8)', 'rgba(245, 158, 11, 0.1)');
    const mediumGradient = createGradient(ctx, 'rgba(251, 191, 36, 0.8)', 'rgba(251, 191, 36, 0.1)');
    const lowGradient = createGradient(ctx, 'rgba(59, 130, 246, 0.8)', 'rgba(59, 130, 246, 0.1)');
    
    // Grid color based on theme
    const gridColor = theme === 'light' ? lightChartColors.gridLines : chartColors.gridLines;
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Critical',
                    data: data.map(item => item.critical),
                    borderColor: chartColors.danger,
                    backgroundColor: criticalGradient,
                    fill: true,
                    tension: 0.4,
                    borderWidth: 3,
                    pointBackgroundColor: chartColors.danger,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                },
                {
                    label: 'High',
                    data: data.map(item => item.high),
                    borderColor: chartColors.warning,
                    backgroundColor: highGradient,
                    fill: true,
                    tension: 0.4,
                    borderWidth: 3,
                    pointBackgroundColor: chartColors.warning,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                },
                {
                    label: 'Medium',
                    data: data.map(item => item.medium),
                    borderColor: chartColors.medium,
                    backgroundColor: mediumGradient,
                    fill: true,
                    tension: 0.4,
                    borderWidth: 3,
                    pointBackgroundColor: chartColors.medium,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                },
                {
                    label: 'Low',
                    data: data.map(item => item.low),
                    borderColor: chartColors.info,
                    backgroundColor: lowGradient,
                    fill: true,
                    tension: 0.4,
                    borderWidth: 3,
                    pointBackgroundColor: chartColors.info,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
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
                        color: gridColor
                    },
                    ticks: {
                        font: {
                            family: "'Inter', sans-serif"
                        }
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        font: {
                            family: "'Inter', sans-serif"
                        }
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        font: {
                            family: "'Inter', sans-serif",
                            size: 12
                        },
                        padding: 20
                    }
                },
                tooltip: {
                    backgroundColor: theme === 'light' ? 'rgba(255, 255, 255, 0.9)' : 'rgba(15, 23, 42, 0.9)',
                    titleColor: theme === 'light' ? '#1E293B' : '#F3F4F6',
                    bodyColor: theme === 'light' ? '#334155' : '#E5E7EB',
                    borderColor: theme === 'light' ? 'rgba(226, 232, 240, 0.5)' : 'rgba(71, 85, 105, 0.5)',
                    borderWidth: 1,
                    padding: 12,
                    boxPadding: 6,
                    usePointStyle: true,
                    titleFont: {
                        family: "'Inter', sans-serif",
                        size: 14,
                        weight: 'bold'
                    },
                    bodyFont: {
                        family: "'Inter', sans-serif",
                        size: 13
                    },
                    cornerRadius: 8,
                    boxWidth: 8
                }
            },
            interaction: {
                mode: 'index',
                intersect: false
            },
            animation: {
                duration: 1500,
                easing: 'easeOutQuart'
            }
        }
    });
}

/**
 * Creates a modern horizontal bar chart for device security comparison with gradients
 * @param {string} elementId - Canvas element ID
 * @param {Array} data - Array of device objects with name and score
 */
function createDeviceComparisonChart(elementId, data) {
    const canvas = document.getElementById(elementId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Get theme
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    
    // Grid color based on theme
    const gridColor = theme === 'light' ? lightChartColors.gridLines : chartColors.gridLines;
    
    // Sort devices by score (ascending)
    data.sort((a, b) => a.score - b.score);
    
    // Create color array with gradients based on scores
    const colorGradients = data.map(device => {
        if (device.score < 4.0) {
            return createGradient(ctx, chartColors.danger, '#F87171');
        } else if (device.score < 5.5) {
            return createGradient(ctx, chartColors.warning, '#FCD34D');
        } else if (device.score < 7.0) {
            return createGradient(ctx, chartColors.medium, '#FDE68A');
        } else {
            return createGradient(ctx, chartColors.success, '#34D399');
        }
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(device => device.name),
            datasets: [{
                label: 'Security Score',
                data: data.map(device => device.score),
                backgroundColor: colorGradients,
                borderWidth: 0,
                borderRadius: 6,
                maxBarThickness: 20
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
                        color: gridColor
                    },
                    ticks: {
                        font: {
                            family: "'Inter', sans-serif"
                        }
                    }
                },
                y: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        font: {
                            family: "'Inter', sans-serif"
                        }
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: theme === 'light' ? 'rgba(255, 255, 255, 0.9)' : 'rgba(15, 23, 42, 0.9)',
                    titleColor: theme === 'light' ? '#1E293B' : '#F3F4F6',
                    bodyColor: theme === 'light' ? '#334155' : '#E5E7EB',
                    borderColor: theme === 'light' ? 'rgba(226, 232, 240, 0.5)' : 'rgba(71, 85, 105, 0.5)',
                    borderWidth: 1,
                    padding: 12,
                    boxPadding: 6,
                    cornerRadius: 8,
                    callbacks: {
                        title: function(tooltipItems) {
                            return tooltipItems[0].label;
                        },
                        label: function(context) {
                            const score = context.parsed.x;
                            let riskLevel = 'Low';
                            
                            if (score < 4.0) riskLevel = 'Critical';
                            else if (score < 5.5) riskLevel = 'High';
                            else if (score < 7.0) riskLevel = 'Medium';
                            
                            return [
                                `Score: ${score.toFixed(1)}/10`,
                                `Risk Level: ${riskLevel}`
                            ];
                        }
                    }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

/**
 * Initialize interactive tooltips
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            animation: true,
            delay: { show: 100, hide: 100 }
        });
    });
}

/**
 * Initialize interactive popovers
 */
function initPopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl, {
            animation: true,
            trigger: 'hover focus',
            delay: { show: 100, hide: 100 }
        });
    });
}

// Initialize tooltips and popovers when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();
    initPopovers();
    
    // Add scroll animation to elements with .animate-on-scroll class
    const animateElements = document.querySelectorAll('.animate-on-scroll');
    if (animateElements.length > 0) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate__animated', 'animate__fadeIn');
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.1
        });
        
        animateElements.forEach(element => {
            observer.observe(element);
        });
    }
});
