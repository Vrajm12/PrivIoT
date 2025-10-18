# PrivIoT - Production-Ready IoT Security Platform

## 🚀 New Production Features

### 1. **Automatic Network Scanning**
Discover IoT devices on your network automatically without manual configuration!

**Features:**
- ✅ Automatic network range detection
- ✅ Device manufacturer identification via MAC address lookup
- ✅ Device type classification (Smart Speaker, Camera, Thermostat, etc.)
- ✅ Open ports detection
- ✅ Firmware version detection
- ✅ One-click device import to dashboard

**How to Use:**
1. Navigate to "Network Scan" in the menu
2. Click "Start Network Scan" (leave network range empty for auto-detect)
3. Review discovered devices
4. Click "Import" on any device to add it to your dashboard

**Note:** Network scanning works best when run with administrator/sudo privileges.

---

### 2. **Multi-Format Report Export**
Generate professional security reports in multiple formats!

**Supported Formats:**
- **PDF**: Full-featured reports with charts, tables, and recommendations
- **CSV**: Spreadsheet-friendly format for data analysis
- **JSON**: Machine-readable format for API integration

**How to Use:**
1. Go to "Reports" section
2. Click on any report to view details
3. Click "Export" dropdown menu
4. Select your desired format (PDF, CSV, or JSON)
5. Report downloads automatically

**PDF Features:**
- Professional formatting with branding
- Security score summary
- Detailed vulnerability tables
- Privacy issues analysis
- Color-coded risk levels
- Actionable recommendations

---

### 3. **Security Trend Analysis**
Track security improvements and identify patterns over time!

**Features:**
- ✅ Device-specific trend analysis
- ✅ Global trends across all devices
- ✅ Interactive charts (Line & Bar charts)
- ✅ Score trending (improving/declining/stable)
- ✅ Vulnerability resolution tracking
- ✅ Risk evolution timeline
- ✅ Personalized recommendations

**How to Use:**
1. Navigate to "Trends" in the menu
2. Select analysis type:
   - **Global**: View trends across all devices
   - **Device**: Analyze a specific device
3. Choose time period (7 days to 6 months)
4. Click "Analyze Trends"

**Metrics Tracked:**
- Overall Security Score
- Security Score
- Privacy Score
- Total Vulnerabilities
- Vulnerabilities by Severity
- Risk Level Changes

---

### 4. **Security Tips & Best Practices**
Personalized security guidance for your specific devices!

**Features:**
- ✅ Personalized recommendations based on your devices
- ✅ Device-specific security tips
- ✅ Priority-based tips (Critical/High/Medium)
- ✅ Interactive security checklist
- ✅ General best practices by category

**Categories:**
- Network Security
- Access Control
- Updates & Maintenance
- Privacy Protection
- Device-Specific Guidance

**How to Use:**
1. Go to "Tips" section
2. Review personalized recommendations at the top
3. Expand accordion sections for device-specific tips
4. Use the interactive checklist to track your progress

---

### 5. **Enhanced Device Management**
User-friendly interface with helpful guidance!

**New Features:**
- ✅ Tooltips and help text throughout the interface
- ✅ Auto-population of device details from network scan
- ✅ Device type presets with common configurations
- ✅ Manufacturer database with OUI lookup
- ✅ Validation and error handling

---

## 🛠️ Installation

### Prerequisites
```bash
Python 3.8+
Virtual environment (recommended)
Administrator/sudo access (for network scanning)
```

### Install Dependencies
```bash
cd PrivIoTShield
pip install -r requirements.txt
```

### New Dependencies Added
- `reportlab>=4.0.0` - PDF generation
- `matplotlib>=3.8.0` - Chart generation
- `pandas>=2.1.0` - Data analysis
- `scapy>=2.5.0` - Network packet manipulation
- `python-nmap>=0.7.1` - Network scanning
- `mac-vendor-lookup>=0.1.12` - MAC address vendor lookup
- `openpyxl>=3.1.2` - Excel file support

### Environment Variables
Create a `.env` file with:
```env
OPENAI_API_KEY=your_openai_api_key_here
SESSION_SECRET=your_secret_key_here
ADMIN_PASSWORD=your_admin_password
```

---

## 🚀 Running the Application

### Development Mode
```bash
python app.py
```
Application will be available at `http://localhost:5000`

### Production Mode
```bash
gunicorn app:app --bind 0.0.0.0:5000 --workers 4
```

---

## 📊 Usage Workflows

### Complete Security Assessment Workflow

1. **Discover Devices**
   - Go to Network Scan
   - Start automatic discovery
   - Import devices to dashboard

2. **Initial Security Scan**
   - Go to Devices
   - Click "Scan" on each device
   - Wait for scan completion

3. **Review Results**
   - Check Dashboard for overall status
   - View individual device details
   - Read vulnerability descriptions

4. **Export Reports**
   - Go to Reports
   - Select report
   - Export as PDF/CSV/JSON

5. **Track Progress**
   - Go to Trends
   - Analyze security improvements
   - Review recommendations

6. **Apply Fixes**
   - Go to Remediation
   - Follow automated remediation steps
   - Rescan to verify fixes

7. **Learn & Improve**
   - Visit Tips section
   - Review personalized recommendations
   - Complete security checklist

---

## 🔒 Security Best Practices

### Network Scanning
- Run scans from a trusted network
- Use dedicated admin account
- Schedule regular scans (weekly recommended)
- Review and validate discovered devices

### Report Management
- Keep reports confidential
- Use secure channels for sharing
- Export reports to encrypted storage
- Regularly archive old reports

### Credential Management
- Change default passwords immediately
- Use unique passwords per device
- Enable 2FA when available
- Store credentials securely

---

## 🏗️ Architecture

### New Modules

#### `export_service.py`
Handles multi-format report generation:
- PDF generation with ReportLab
- CSV export with proper formatting
- JSON serialization with metadata
- Chart generation with Matplotlib

#### `network_scanner.py`
Automatic device discovery:
- Network range detection
- ARP table parsing
- Port scanning
- MAC vendor lookup
- Device fingerprinting

#### `trend_analysis.py`
Security trend tracking:
- Time-series analysis
- Score trending
- Vulnerability tracking
- Risk evolution
- Recommendation generation

---

## 📈 Performance Considerations

### Network Scanning
- Scans limited to first 50 IPs for performance
- Configurable timeout settings
- Async operations for bulk scanning
- Caching for MAC vendor lookups

### Report Generation
- Lazy loading for large datasets
- Pagination for vulnerability lists
- Optimized PDF rendering
- Efficient chart generation

### Trend Analysis
- Query optimization with indexes
- Data aggregation at database level
- Caching for frequently accessed trends
- Configurable time windows

---

## 🐛 Troubleshooting

### Network Scanning Issues
**Problem**: No devices found
- **Solution**: Ensure you're on the same network as devices
- **Solution**: Run with administrator/sudo privileges
- **Solution**: Check firewall settings

**Problem**: Incorrect manufacturer information
- **Solution**: MAC vendor database may need updating
- **Solution**: Manually verify device information

### Report Export Issues
**Problem**: PDF generation fails
- **Solution**: Ensure reportlab is installed correctly
- **Solution**: Check write permissions in output directory

**Problem**: Large reports timeout
- **Solution**: Limit report scope
- **Solution**: Increase timeout settings

### Trend Analysis Issues
**Problem**: Insufficient data for trends
- **Solution**: Run more scans (minimum 2 scans needed)
- **Solution**: Adjust time period

---

## 🔄 Future Enhancements

### Planned Features
- [ ] Real-time network monitoring
- [ ] Automated remediation scheduling
- [ ] Email/SMS alert notifications
- [ ] Integration with SIEM systems
- [ ] Mobile app support
- [ ] Multi-user collaboration
- [ ] Custom compliance frameworks
- [ ] API rate limiting
- [ ] Advanced filtering and search
- [ ] Batch operations

---

## 📞 Support

For issues, questions, or feature requests:
- Create an issue on GitHub
- Check documentation
- Review security tips section

---

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

---

## 🙏 Acknowledgments

- OpenAI for AI-powered analysis
- ReportLab for PDF generation
- Matplotlib for chart generation
- Scapy for network operations
- Bootstrap for UI components
- Chart.js for interactive visualizations

---

## 🔐 Security Disclosure

If you discover a security vulnerability, please email security@priviot.io instead of using the public issue tracker.

---

**Made with ❤️ for IoT Security**
