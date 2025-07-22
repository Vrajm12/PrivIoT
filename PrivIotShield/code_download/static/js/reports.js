// reports.js - Handles report listing and viewing functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Setup report type filter
    setupReportFilter();
    
    // Setup report date formatting
    formatReportDates();
    
    // Setup report export functionality
    setupReportExport();
    
    // Setup report sharing functionality
    setupReportSharing();
});

/**
 * Setup report type filtering functionality
 */
function setupReportFilter() {
    const filterSelect = document.getElementById('reportTypeFilter');
    if (!filterSelect) return;
    
    filterSelect.addEventListener('change', function() {
        const selectedType = this.value;
        const reportCards = document.querySelectorAll('.report-card');
        
        reportCards.forEach(card => {
            if (selectedType === 'all' || card.dataset.reportType === selectedType) {
                card.classList.remove('d-none');
            } else {
                card.classList.add('d-none');
            }
        });
        
        // Update count
        const visibleCount = document.querySelectorAll('.report-card:not(.d-none)').length;
        const countElement = document.getElementById('reportCount');
        if (countElement) {
            countElement.textContent = visibleCount;
        }
    });
}

/**
 * Format all report dates to a user-friendly format
 */
function formatReportDates() {
    const dateElements = document.querySelectorAll('.report-date');
    
    dateElements.forEach(element => {
        const isoDate = element.dataset.date;
        if (isoDate) {
            const date = new Date(isoDate);
            
            // Format: "Jan 15, 2023 at 2:30 PM"
            const formattedDate = date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            }) + ' at ' + date.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit'
            });
            
            element.textContent = formattedDate;
        }
    });
}

/**
 * Setup report export functionality
 */
function setupReportExport() {
    const exportButtons = document.querySelectorAll('.report-export-btn');
    
    exportButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const reportId = this.dataset.reportId;
            const reportType = this.dataset.exportType || 'pdf';
            
            // Show loading state
            const originalText = this.innerHTML;
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Exporting...';
            this.disabled = true;
            
            // In a real app, this would be an API call to export the report
            // For this demo, we'll simulate it with a timeout
            setTimeout(() => {
                this.innerHTML = originalText;
                this.disabled = false;
                
                // Show success message
                const toast = new bootstrap.Toast(document.getElementById('exportSuccessToast'));
                toast.show();
                
                console.log(`Exporting report ${reportId} as ${reportType}`);
            }, 2000);
        });
    });
}

/**
 * Setup report sharing functionality
 */
function setupReportSharing() {
    const shareButtons = document.querySelectorAll('.report-share-btn');
    
    shareButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const reportId = this.dataset.reportId;
            const reportTitle = this.dataset.reportTitle || 'Security Report';
            
            // Set up share modal content
            const shareModal = document.getElementById('shareReportModal');
            if (shareModal) {
                const modalTitle = shareModal.querySelector('.modal-title');
                if (modalTitle) {
                    modalTitle.textContent = `Share "${reportTitle}"`;
                }
                
                const reportLinkInput = shareModal.querySelector('#reportShareLink');
                if (reportLinkInput) {
                    // Generate a sample report URL
                    const reportUrl = `${window.location.origin}/report/${reportId}?share=true`;
                    reportLinkInput.value = reportUrl;
                }
                
                // Show the modal
                const modal = new bootstrap.Modal(shareModal);
                modal.show();
            }
        });
    });
    
    // Setup copy link button
    const copyLinkBtn = document.getElementById('copyReportLinkBtn');
    if (copyLinkBtn) {
        copyLinkBtn.addEventListener('click', function() {
            const linkInput = document.getElementById('reportShareLink');
            if (linkInput) {
                linkInput.select();
                document.execCommand('copy');
                
                // Change button text temporarily
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                
                setTimeout(() => {
                    this.textContent = originalText;
                }, 2000);
            }
        });
    }
}

/**
 * Previews a report in a modal
 * @param {number} reportId - The ID of the report to preview
 */
function previewReport(reportId) {
    // In a real app, this would fetch the report content
    // For this demo, we'll just show a modal with placeholder content
    
    const previewModal = document.getElementById('reportPreviewModal');
    if (previewModal) {
        const modalTitle = previewModal.querySelector('.modal-title');
        const modalBody = previewModal.querySelector('.modal-body');
        
        if (modalTitle && modalBody) {
            // Find the report card to get its title
            const reportCard = document.querySelector(`.report-card[data-report-id="${reportId}"]`);
            if (reportCard) {
                const titleElement = reportCard.querySelector('.report-title');
                if (titleElement) {
                    modalTitle.textContent = titleElement.textContent;
                }
            }
            
            // Show loading state
            modalBody.innerHTML = `
                <div class="text-center py-5">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-3">Loading report preview...</p>
                </div>
            `;
            
            // Show the modal
            const modal = new bootstrap.Modal(previewModal);
            modal.show();
            
            // In a real app, fetch the report content from the server
            // For this demo, simulate loading with a timeout
            setTimeout(() => {
                // Replace with sample content
                modalBody.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        This is a preview of report #${reportId}. For the full report, please click "View Full Report".
                    </div>
                    <div class="report-preview-content">
                        <h4>Executive Summary</h4>
                        <p>This security assessment identified several vulnerabilities that require attention. The overall security score is moderate, with specific concerns in data encryption and access controls.</p>
                        
                        <h4>Key Findings</h4>
                        <ul>
                            <li>3 Critical vulnerabilities</li>
                            <li>5 High-risk issues</li>
                            <li>Outdated firmware detected</li>
                            <li>Inadequate encryption for sensitive data</li>
                        </ul>
                        
                        <div class="text-center my-4">
                            <p class="text-muted">Preview truncated. View the full report for complete details.</p>
                        </div>
                    </div>
                    <div class="text-end">
                        <a href="/report/${reportId}" class="btn btn-primary">View Full Report</a>
                    </div>
                `;
            }, 1500);
        }
    }
}
