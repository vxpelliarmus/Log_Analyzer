"""
CloudLog Pro - Enterprise-grade Log Analyzer
A modern, feature-rich log analysis tool for cloud environments
Author: CloudLog Pro Team
Version: 3.0.0
"""

import os
import re
import json
import uuid
import gzip
import hashlib
import logging
import secrets
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from functools import wraps
from pathlib import Path
import socket
import platform

from flask import (
    Flask, request, render_template_string, jsonify, 
    session, redirect, url_for, flash, make_response, send_file
)
from werkzeug.utils import secure_filename

# Optional imports with fallbacks
try:
    import plotly
    import plotly.graph_objs as go
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("⚠️ Plotly not installed. Charts will be disabled. Install with: pip install plotly")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from user_agents import parse as parse_ua
    UA_AVAILABLE = True
except ImportError:
    UA_AVAILABLE = False
    print("⚠️ user-agents not installed. Device detection will be limited. Install with: pip install user-agents")

# ============================================================================
# Configuration
# ============================================================================

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    ALLOWED_EXTENSIONS = {'log', 'txt', 'csv', 'gz'}
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    # Use /tmp for Render.com (ephemeral storage)
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/cloudlog_uploads')
    CACHE_FOLDER = os.environ.get('CACHE_FOLDER', '/tmp/cloudlog_cache')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = False
    
    # Analysis settings - Optimized for 512MB RAM
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB (reduced for free tier)
    CHUNK_SIZE = 512 * 1024  # 512KB chunks (reduced for memory)
    MAX_LINES_PER_FILE = 500000  # Reduced for free tier
    DEFAULT_TIMEZONE = 'UTC'

# Create necessary directories
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.CACHE_FOLDER, exist_ok=True)

# ============================================================================
# Advanced Logging Setup
# ============================================================================

class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging"""
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'module': record.module,
            'line': record.lineno,
            'message': record.getMessage(),
            'hostname': socket.gethostname(),
            'pid': os.getpid()
        }
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

# Setup logging
logger = logging.getLogger('cloudlog')
logger.setLevel(logging.INFO)

# Console handler (for Render.com logs)
console_handler = logging.StreamHandler()
console_handler.setFormatter(JSONFormatter())
logger.addHandler(console_handler)

# File handler for persistent logs (optional)
try:
    log_file = '/tmp/cloudlog_app.log'
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)
except:
    pass  # Continue without file handler if can't write

# ============================================================================
# Data Models (unchanged - keeping all functionality)
# ============================================================================

@dataclass
class LogEntry:
    """Comprehensive log entry model"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None
    ip_address: str = ''
    method: str = ''
    path: str = ''
    protocol: str = 'HTTP/1.1'
    status_code: int = 0
    response_size: int = 0
    referer: str = ''
    user_agent: str = ''
    request_time: float = 0.0
    cache_status: str = '-'
    geo_location: Dict[str, str] = field(default_factory=lambda: {'country': 'Unknown', 'city': 'Unknown'})
    device_type: str = 'unknown'
    browser: str = 'unknown'
    os: str = 'unknown'
    is_bot: bool = False
    raw_line: str = ''
    
    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class TimeSeriesData:
    """Time series data for trends"""
    timestamps: List[str] = field(default_factory=list)
    request_counts: List[int] = field(default_factory=list)
    error_counts: List[int] = field(default_factory=list)

@dataclass
class AnalysisReport:
    """Comprehensive analysis report"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    filename: str = ''
    analysis_date: str = field(default_factory=lambda: datetime.now().isoformat())
    total_requests: int = 0
    unique_visitors: int = 0
    total_bandwidth: float = 0.0  # in MB
    error_rate: float = 0.0
    success_rate: float = 0.0
    
    status_codes: Dict[str, int] = field(default_factory=dict)
    http_methods: Dict[str, int] = field(default_factory=dict)
    top_paths: List[Tuple[str, int]] = field(default_factory=list)
    top_ips: List[Tuple[str, Dict]] = field(default_factory=list)
    top_referrers: List[Tuple[str, int]] = field(default_factory=list)
    
    hourly_traffic: Dict[str, int] = field(default_factory=dict)
    device_breakdown: Dict[str, int] = field(default_factory=dict)
    browser_breakdown: Dict[str, int] = field(default_factory=dict)
    os_breakdown: Dict[str, int] = field(default_factory=dict)
    bot_traffic: int = 0
    
    time_series: TimeSeriesData = field(default_factory=TimeSeriesData)
    anomalies: List[Dict] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    
    performance_score: int = 100
    security_score: int = 100
    recommendations: List[str] = field(default_factory=list)

# ============================================================================
# Enhanced Log Parser (unchanged - keeping all functionality)
# ============================================================================

class EnhancedLogParser:
    """Advanced log parser with multiple format support"""
    
    # Common log patterns
    PATTERNS = {
        'combined': re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+)(?:[^"]*?)" '
            r'(?P<status>\d{3}) (?P<size>\S+) '
            r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
        ),
        'common': re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
            r'(?P<status>\d{3}) (?P<size>\S+)'
        ),
        'simple': re.compile(
            r'(?P<ip>\S+) .*? "(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) '
            r'(?P<path>\S+) .*?" (?P<status>\d{3})'
        )
    }
    
    @classmethod
    def parse_timestamp(cls, timestamp_str: str) -> Optional[str]:
        """Parse timestamp to ISO format"""
        try:
            # Try common formats
            for fmt in ['%d/%b/%Y:%H:%M:%S %z', '%Y-%m-%dT%H:%M:%S%z', '%d/%b/%Y:%H:%M:%S']:
                try:
                    dt = datetime.strptime(timestamp_str.strip('[]'), fmt)
                    return dt.isoformat()
                except (ValueError, TypeError):
                    continue
        except:
            pass
        return None
    
    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEntry]:
        """Parse a log line"""
        
        for pattern_name, pattern in cls.PATTERNS.items():
            match = pattern.search(line)
            if match:
                try:
                    entry = LogEntry(raw_line=line[:200])
                    
                    # Basic fields
                    entry.ip_address = match.group("ip")
                    entry.method = match.group("method")
                    entry.path = match.group("path")
                    entry.status_code = int(match.group("status"))
                    
                    # Optional fields
                    if "size" in match.groupdict() and match.group("size") not in ('-', ''):
                        try:
                            entry.response_size = int(match.group("size"))
                        except:
                            pass
                    
                    if "referer" in match.groupdict():
                        entry.referer = match.group("referer")[:200]
                    
                    if "ua" in match.groupdict():
                        entry.user_agent = match.group("ua")[:200]
                        cls._enrich_user_agent(entry)
                    
                    if "timestamp" in match.groupdict():
                        entry.timestamp = cls.parse_timestamp(match.group("timestamp"))
                    
                    # Simple geo mock
                    cls._enrich_geolocation(entry)
                    
                    return entry
                    
                except Exception as e:
                    logger.debug(f"Error parsing line: {e}")
                    continue
        
        return None
    
    @classmethod
    def _enrich_user_agent(cls, entry: LogEntry):
        """Parse user agent data"""
        if not entry.user_agent or not UA_AVAILABLE:
            return
        
        try:
            ua = parse_ua(entry.user_agent)
            entry.browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
            entry.os = f"{ua.os.family} {ua.os.version_string}".strip()
            entry.device_type = 'mobile' if ua.is_mobile else 'tablet' if ua.is_tablet else 'pc' if ua.is_pc else 'bot' if ua.is_bot else 'unknown'
            entry.is_bot = ua.is_bot
        except:
            pass
    
    @classmethod
    def _enrich_geolocation(cls, entry: LogEntry):
        """Mock geolocation data"""
        # Simple mock based on IP first octet
        try:
            first_octet = entry.ip_address.split('.')[0]
            mock_locations = {
                '192': {'country': 'United States', 'city': 'New York'},
                '10': {'country': 'United Kingdom', 'city': 'London'},
                '172': {'country': 'Germany', 'city': 'Berlin'},
                '8': {'country': 'United States', 'city': 'Mountain View'},
                '1': {'country': 'Australia', 'city': 'Sydney'}
            }
            entry.geo_location = mock_locations.get(first_octet, {'country': 'Unknown', 'city': 'Unknown'})
        except:
            pass

# ============================================================================
# Analytics Engine (unchanged - keeping all functionality)
# ============================================================================

class AnalyticsEngine:
    """Analytics engine for log analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def analyze(self, entries: List[LogEntry], filename: str) -> AnalysisReport:
        """Perform comprehensive analysis on log entries"""
        report = AnalysisReport(filename=filename)
        
        if not entries:
            return report
        
        # Basic metrics
        report.total_requests = len(entries)
        report.unique_visitors = len(set(e.ip_address for e in entries if e.ip_address))
        report.total_bandwidth = sum(e.response_size for e in entries) / (1024 * 1024)  # Convert to MB
        
        # Status codes analysis
        status_counter = Counter(e.status_code for e in entries if e.status_code)
        report.status_codes = {str(k): v for k, v in status_counter.most_common()}
        
        # Error analysis
        errors = sum(1 for e in entries if e.status_code >= 400)
        report.error_rate = (errors / report.total_requests) * 100 if report.total_requests > 0 else 0
        report.success_rate = 100 - report.error_rate
        
        # HTTP methods
        method_counter = Counter(e.method for e in entries if e.method)
        report.http_methods = dict(method_counter.most_common())
        
        # Top paths
        path_counter = Counter(e.path for e in entries if e.path)
        report.top_paths = path_counter.most_common(10)
        
        # Top IPs with enrichment
        ip_counter = Counter(e.ip_address for e in entries if e.ip_address)
        report.top_ips = []
        for ip, count in ip_counter.most_common(10):
            ip_entries = [e for e in entries if e.ip_address == ip]
            report.top_ips.append((
                ip, 
                {
                    'count': count,
                    'geo': ip_entries[0].geo_location if ip_entries else {'country': 'Unknown', 'city': 'Unknown'}
                }
            ))
        
        # Referrers
        referrer_counter = Counter(e.referer for e in entries if e.referer and e.referer not in ('-', ''))
        report.top_referrers = referrer_counter.most_common(5)
        
        # Device breakdown
        device_counter = Counter(e.device_type for e in entries if e.device_type != 'unknown')
        report.device_breakdown = dict(device_counter.most_common())
        
        browser_counter = Counter(e.browser for e in entries if e.browser != 'unknown')
        report.browser_breakdown = dict(browser_counter.most_common(5))
        
        os_counter = Counter(e.os for e in entries if e.os != 'unknown')
        report.os_breakdown = dict(os_counter.most_common(5))
        
        report.bot_traffic = sum(1 for e in entries if e.is_bot)
        
        # Time series analysis
        self._analyze_time_series(entries, report)
        
        # Detect anomalies
        self._detect_anomalies(entries, report)
        
        # Generate insights
        self._generate_insights(report)
        
        # Calculate scores
        self._calculate_scores(report)
        
        # Generate recommendations
        self._generate_recommendations(report)
        
        return report
    
    def _analyze_time_series(self, entries: List[LogEntry], report: AnalysisReport):
        """Analyze time-based patterns"""
        hourly_data = defaultdict(lambda: {'requests': 0, 'errors': 0})
        
        for entry in entries:
            if entry.timestamp:
                try:
                    hour_key = entry.timestamp[:13] + ':00'  # Simple hour grouping
                    hourly_data[hour_key]['requests'] += 1
                    if entry.status_code >= 400:
                        hourly_data[hour_key]['errors'] += 1
                except:
                    pass
        
        # Sort by timestamp
        sorted_hours = sorted(hourly_data.keys())
        
        report.time_series.timestamps = sorted_hours[-24:]  # Last 24 hours
        report.time_series.request_counts = [hourly_data[h]['requests'] for h in sorted_hours[-24:]]
        report.time_series.error_counts = [hourly_data[h]['errors'] for h in sorted_hours[-24:]]
        
        # Hourly traffic
        for i, hour in enumerate(sorted_hours[-24:]):
            report.hourly_traffic[hour] = hourly_data[hour]['requests']
    
    def _detect_anomalies(self, entries: List[LogEntry], report: AnalysisReport):
        """Detect anomalies in the log data"""
        if not entries or not NUMPY_AVAILABLE:
            return
        
        try:
            # IP-based anomalies
            ip_counts = Counter(e.ip_address for e in entries if e.ip_address)
            if ip_counts:
                counts = list(ip_counts.values())
                mean_count = np.mean(counts)
                std_count = np.std(counts)
                
                for ip, count in ip_counts.items():
                    if count > mean_count + 3 * std_count:
                        report.anomalies.append({
                            'type': 'high_traffic_ip',
                            'ip': ip,
                            'requests': count,
                            'severity': 'high' if count > mean_count + 5 * std_count else 'medium'
                        })
        except:
            pass
    
    def _generate_insights(self, report: AnalysisReport):
        """Generate insights from the data"""
        insights = []
        
        if report.total_requests > 10000:
            insights.append(f"High traffic volume detected: {report.total_requests:,} requests")
        
        if report.error_rate > 10:
            insights.append(f"High error rate ({report.error_rate:.1f}%) - investigate 4xx/5xx responses")
        
        if report.bot_traffic > 0:
            bot_percentage = (report.bot_traffic / report.total_requests) * 100
            if bot_percentage > 20:
                insights.append(f"Significant bot traffic ({bot_percentage:.1f}%) - consider bot management")
        
        if report.top_paths:
            insights.append(f"Most popular path: {report.top_paths[0][0]} ({report.top_paths[0][1]:,} requests)")
        
        if report.unique_visitors < report.total_requests * 0.1:
            insights.append("Low unique visitor ratio - possible scraping or bot activity")
        
        if not insights:
            insights.append("System appears healthy - continue monitoring")
            insights.append("Set up regular log analysis for proactive monitoring")
        
        report.insights = insights
    
    def _calculate_scores(self, report: AnalysisReport):
        """Calculate performance and security scores"""
        # Performance score
        perf_score = 100
        if report.error_rate > 5:
            perf_score -= min((report.error_rate - 5) * 2, 40)
        if report.total_requests > 100000:
            perf_score -= 10
        report.performance_score = max(0, min(100, int(perf_score)))
        
        # Security score
        sec_score = 100
        for anomaly in report.anomalies:
            if anomaly['severity'] == 'high':
                sec_score -= 15
            else:
                sec_score -= 5
        
        # Check for security-sensitive paths
        sensitive_paths = ['admin', 'login', 'wp-admin', '.git', '.env', 'config']
        for path, _ in report.top_paths:
            if any(sp in path.lower() for sp in sensitive_paths):
                sec_score -= 10
                break
        
        report.security_score = max(0, min(100, sec_score))
    
    def _generate_recommendations(self, report: AnalysisReport):
        """Generate actionable recommendations"""
        recommendations = []
        
        if report.error_rate > 5:
            recommendations.append("Investigate and fix recurring errors (4xx/5xx responses)")
        
        if report.security_score < 70:
            recommendations.append("Review security configuration - potential vulnerabilities detected")
        
        if report.performance_score < 70:
            recommendations.append("Optimize performance - consider caching or CDN implementation")
        
        if report.total_requests > 0 and report.bot_traffic / report.total_requests > 0.3:
            recommendations.append("Implement bot mitigation strategies (rate limiting, CAPTCHA)")
        
        if len(report.anomalies) > 0:
            recommendations.append("Investigate detected anomalies - unusual patterns found")
        
        if not recommendations:
            recommendations.append("System appears healthy - continue monitoring")
            recommendations.append("Set up regular log analysis for proactive monitoring")
        
        report.recommendations = recommendations

# ============================================================================
# Visualization Generator (Simplified)
# ============================================================================

class VisualizationGenerator:
    """Generate visualizations for the report"""
    
    @staticmethod
    def create_traffic_chart(report: AnalysisReport) -> Optional[str]:
        """Create traffic time series chart"""
        if not PLOTLY_AVAILABLE or not report.time_series.timestamps:
            return None
        
        try:
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=report.time_series.timestamps,
                y=report.time_series.request_counts,
                mode='lines+markers',
                name='Total Requests',
                line=dict(color='#3b82f6', width=3),
                marker=dict(size=6)
            ))
            
            fig.add_trace(go.Scatter(
                x=report.time_series.timestamps,
                y=report.time_series.error_counts,
                mode='lines+markers',
                name='Errors',
                line=dict(color='#ef4444', width=2, dash='dash'),
                marker=dict(size=4)
            ))
            
            fig.update_layout(
                title='Traffic Analysis Over Time',
                xaxis_title='Time',
                yaxis_title='Request Count',
                hovermode='x unified',
                template='plotly_white',
                height=400,
                margin=dict(l=50, r=50, t=50, b=50)
            )
            
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
        except:
            return None
    
    @staticmethod
    def create_status_chart(report: AnalysisReport) -> Optional[str]:
        """Create status code distribution chart"""
        if not PLOTLY_AVAILABLE or not report.status_codes:
            return None
        
        try:
            # Group status codes
            categories = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0}
            colors = ['#10b981', '#f59e0b', '#ef4444', '#8b5cf6']
            
            for code, count in report.status_codes.items():
                if code.startswith('2'):
                    categories['2xx'] += count
                elif code.startswith('3'):
                    categories['3xx'] += count
                elif code.startswith('4'):
                    categories['4xx'] += count
                elif code.startswith('5'):
                    categories['5xx'] += count
            
            # Filter out zero values
            labels = [k for k, v in categories.items() if v > 0]
            values = [v for v in categories.values() if v > 0]
            
            fig = go.Figure(data=[
                go.Pie(
                    labels=labels,
                    values=values,
                    marker=dict(colors=colors[:len(labels)]),
                    textinfo='label+percent',
                    hole=0.3
                )
            ])
            
            fig.update_layout(
                title='Status Code Distribution',
                height=350,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
        except:
            return None
    
    @staticmethod
    def create_device_chart(report: AnalysisReport) -> Optional[str]:
        """Create device breakdown chart"""
        if not PLOTLY_AVAILABLE or not report.device_breakdown:
            return None
        
        try:
            colors = {'mobile': '#3b82f6', 'tablet': '#8b5cf6', 'pc': '#10b981', 'bot': '#ef4444'}
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(report.device_breakdown.keys()),
                    y=list(report.device_breakdown.values()),
                    marker_color=[colors.get(k, '#94a3b8') for k in report.device_breakdown.keys()],
                    text=list(report.device_breakdown.values()),
                    textposition='auto',
                )
            ])
            
            fig.update_layout(
                title='Device Breakdown',
                xaxis_title='Device Type',
                yaxis_title='Request Count',
                height=350,
                margin=dict(l=40, r=40, t=40, b=40)
            )
            
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
        except:
            return None

# ============================================================================
# Flask Application
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize components
parser = EnhancedLogParser()
analytics = AnalyticsEngine()
viz = VisualizationGenerator()

# ============================================================================
# HTML Template (unchanged - keeping all UI functionality)
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudLog Pro - Enterprise Log Analyzer</title>
    
    <!-- Fonts and Icons -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <!-- Plotly -->
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --primary-light: #93c5fd;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --light: #f9fafb;
            --gray: #6b7280;
            --border: #e5e7eb;
            
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1);
            
            --radius-sm: 0.375rem;
            --radius: 0.5rem;
            --radius-lg: 0.75rem;
            --radius-xl: 1rem;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: var(--dark);
            line-height: 1.5;
        }
        
        /* Navigation */
        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            box-shadow: var(--shadow);
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .nav-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 800;
            color: var(--primary);
            text-decoration: none;
        }
        
        .logo i {
            font-size: 2rem;
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
            align-items: center;
        }
        
        .nav-links a {
            color: var(--gray);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .nav-links a:hover,
        .nav-links a.active {
            color: var(--primary);
        }
        
        /* Main Container */
        .container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        
        /* Hero Section */
        .hero {
            text-align: center;
            color: white;
            padding: 4rem 2rem;
            margin-bottom: 2rem;
            background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%);
            backdrop-filter: blur(10px);
            border-radius: var(--radius-xl);
            box-shadow: var(--shadow-lg);
        }
        
        .hero h1 {
            font-size: 3.5rem;
            font-weight: 800;
            margin-bottom: 1rem;
            letter-spacing: -0.02em;
        }
        
        .hero p {
            font-size: 1.25rem;
            opacity: 0.95;
            max-width: 600px;
            margin: 0 auto;
        }
        
        /* Upload Card */
        .upload-card {
            background: white;
            border-radius: var(--radius-xl);
            box-shadow: var(--shadow-xl);
            overflow: hidden;
            margin-bottom: 2rem;
            transition: transform 0.3s;
        }
        
        .upload-card:hover {
            transform: translateY(-4px);
        }
        
        .upload-header {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .upload-header h2 {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .upload-header p {
            opacity: 0.9;
        }
        
        .upload-body {
            padding: 3rem;
        }
        
        /* FIXED: Upload area with proper icon size and single-click handling */
        .upload-area {
            border: 3px dashed var(--border);
            border-radius: var(--radius-lg);
            padding: 2.5rem 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: var(--light);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            position: relative;
            z-index: 1;
        }
        
        .upload-area:hover {
            border-color: var(--primary);
            background: #eff6ff;
        }
        
        .upload-area i {
            font-size: 3rem;
            color: var(--primary);
            margin-bottom: 0.5rem;
            display: block;
            line-height: 1;
            pointer-events: none;
        }
        
        .upload-area h3 {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--dark);
            margin: 0;
            pointer-events: none;
        }
        
        .upload-area p {
            color: var(--gray);
            margin: 0;
            font-size: 0.9rem;
            pointer-events: none;
        }
        
        .file-input {
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            opacity: 0;
            cursor: pointer;
            z-index: 2;
        }
        
        .file-info {
            margin-top: 1rem;
            padding: 1rem;
            background: #eff6ff;
            border-radius: var(--radius);
            display: none;
            align-items: center;
            gap: 0.5rem;
        }
        
        .file-info.active {
            display: flex;
        }
        
        .file-info i {
            font-size: 1.2rem;
            color: var(--primary);
        }
        
        .file-name {
            font-weight: 600;
            color: var(--primary-dark);
            word-break: break-all;
        }
        
        .btn {
            display: inline-block;
            padding: 0.75rem 2rem;
            border: none;
            border-radius: var(--radius);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            box-shadow: var(--shadow);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }
        
        .btn-secondary {
            background: white;
            color: var(--primary);
            border: 2px solid var(--primary);
        }
        
        .btn-secondary:hover {
            background: var(--primary);
            color: white;
        }
        
        .btn-large {
            padding: 1rem 3rem;
            font-size: 1.125rem;
        }
        
        .btn-group {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 2rem;
        }
        
        /* Loading Overlay */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }
        
        .loading-overlay.active {
            display: flex;
        }
        
        .loading-content {
            background: white;
            padding: 3rem;
            border-radius: var(--radius-xl);
            text-align: center;
            animation: slideIn 0.3s;
        }
        
        .loading-spinner {
            width: 60px;
            height: 60px;
            border: 4px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1.5rem;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow);
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }
        
        .stat-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--primary-light), var(--primary));
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1rem;
        }
        
        .stat-icon i {
            font-size: 1.5rem;
            color: white;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: var(--gray);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 800;
            color: var(--dark);
            margin-bottom: 0.25rem;
        }
        
        /* Charts Grid */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .chart-card {
            background: white;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow);
            overflow: hidden;
        }
        
        .chart-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            background: var(--light);
        }
        
        .chart-header h3 {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--dark);
            margin-bottom: 0.25rem;
        }
        
        .chart-body {
            padding: 1.5rem;
            height: 400px;
        }
        
        /* Data Tables */
        .tables-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .table-card {
            background: white;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow);
            overflow: hidden;
        }
        
        .table-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            background: var(--light);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .table-header h3 {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--dark);
        }
        
        .table-body {
            padding: 1.5rem;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .data-table th {
            text-align: left;
            padding: 0.75rem;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--gray);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 2px solid var(--border);
        }
        
        .data-table td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
            color: var(--dark);
        }
        
        .data-table tr:hover td {
            background: var(--light);
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-success {
            background: #d1fae5;
            color: #065f46;
        }
        
        .badge-warning {
            background: #fef3c7;
            color: #92400e;
        }
        
        .badge-danger {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .badge-info {
            background: #dbeafe;
            color: #1e40af;
        }
        
        /* Insights Cards */
        .insights-section {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .insights-card {
            background: white;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow);
            overflow: hidden;
        }
        
        .insights-header {
            padding: 1.5rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }
        
        .insights-header h3 {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        
        .insights-body {
            padding: 1.5rem;
        }
        
        .insight-item {
            display: flex;
            gap: 1rem;
            padding: 1rem 0;
            border-bottom: 1px solid var(--border);
        }
        
        .insight-item:last-child {
            border-bottom: none;
        }
        
        .insight-icon {
            width: 40px;
            height: 40px;
            background: var(--light);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
            font-size: 1.25rem;
        }
        
        .insight-content {
            flex: 1;
        }
        
        .insight-title {
            font-weight: 600;
            color: var(--dark);
            margin-bottom: 0.25rem;
        }
        
        .insight-description {
            font-size: 0.875rem;
            color: var(--gray);
        }
        
        .recommendation-item {
            display: flex;
            gap: 1rem;
            padding: 1rem;
            background: var(--light);
            border-radius: var(--radius);
            margin-bottom: 0.5rem;
        }
        
        .recommendation-icon {
            color: var(--primary);
            font-size: 1.25rem;
        }
        
        .recommendation-text {
            flex: 1;
            font-size: 0.875rem;
            color: var(--dark);
        }
        
        /* Flash Messages */
        .flash-messages {
            position: fixed;
            top: 100px;
            right: 20px;
            z-index: 1000;
        }
        
        .flash-message {
            background: white;
            border-radius: var(--radius);
            box-shadow: var(--shadow-lg);
            padding: 1rem 1.5rem;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            animation: slideInRight 0.3s;
        }
        
        .flash-success {
            border-left: 4px solid var(--success);
        }
        
        .flash-error {
            border-left: 4px solid var(--danger);
        }
        
        .flash-warning {
            border-left: 4px solid var(--warning);
        }
        
        .flash-info {
            border-left: 4px solid var(--primary);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            color: white;
            padding: 3rem 2rem;
            margin-top: 4rem;
            background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%);
            backdrop-filter: blur(10px);
            border-radius: var(--radius-xl);
        }
        
        /* Animations */
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        @keyframes slideIn {
            from {
                transform: translateY(-20px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        
        @keyframes slideInRight {
            from {
                transform: translateX(20px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .nav-container {
                flex-direction: column;
                gap: 1rem;
            }
            
            .nav-links {
                flex-wrap: wrap;
                justify-content: center;
            }
            
            .hero h1 {
                font-size: 2rem;
            }
            
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .tables-grid {
                grid-template-columns: 1fr;
            }
            
            .insights-section {
                grid-template-columns: 1fr;
            }
            
            .btn-group {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <h3>Analyzing Your Logs</h3>
            <p>This may take a few moments...</p>
        </div>
    </div>
    
    <!-- Navigation -->
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="logo">
                <i class="fas fa-cloud-upload-alt"></i>
                <span>CloudLog Pro</span>
            </a>
            <div class="nav-links">
                <a href="/" class="active">
                    <i class="fas fa-home"></i>
                    Home
                </a>
                <a href="#">
                    <i class="fas fa-chart-line"></i>
                    Features
                </a>
                <a href="#">
                    <i class="fas fa-book"></i>
                    Docs
                </a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <!-- Flash Messages -->
        <div class="flash-messages" id="flashMessages">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="flash-message flash-{{ category }}">
                            <i class="fas fa-{% if category == 'success' %}check-circle{% elif category == 'error' %}exclamation-circle{% elif category == 'warning' %}exclamation-triangle{% else %}info-circle{% endif %}"></i>
                            <span>{{ message }}</span>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
        </div>
        
        <!-- Hero Section -->
        <div class="hero">
            <h1>Enterprise Log Analysis</h1>
            <p>Transform your raw logs into actionable insights with advanced analytics</p>
        </div>
        
        <!-- Upload Card -->
        <div class="upload-card">
            <div class="upload-header">
                <h2><i class="fas fa-cloud-upload-alt"></i> Upload Log File</h2>
                <p>Support for Apache, Nginx, and common log formats</p>
            </div>
            <div class="upload-body">
                <form method="post" enctype="multipart/form-data" id="uploadForm">
                    <!-- FIXED: Upload area with proper icon size and single-click -->
                    <div class="upload-area" id="uploadArea">
                        <i class="fas fa-cloud-upload-alt"></i>
                        <h3>Drag & drop or click to browse</h3>
                        <p>Supported formats: .log, .txt, .csv, .gz (Max: 50MB)</p>
                        <input type="file" id="fileInput" name="logfile" class="file-input" accept=".log,.txt,.csv,.gz" required>
                    </div>
                    
                    <div class="file-info" id="fileInfo">
                        <i class="fas fa-file-alt"></i>
                        <span>Selected file: <span class="file-name" id="fileName"></span></span>
                    </div>
                    
                    <div class="btn-group">
                        <button type="submit" class="btn btn-primary btn-large" id="submitBtn">
                            <i class="fas fa-chart-bar"></i>
                            Analyze Logs
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        {% if report %}
        <!-- Results Section -->
        <div class="results-section">
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <div class="stat-label">Total Requests</div>
                    <div class="stat-value">{{ "{:,}".format(report.total_requests) }}</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-label">Unique Visitors</div>
                    <div class="stat-value">{{ "{:,}".format(report.unique_visitors) }}</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-database"></i>
                    </div>
                    <div class="stat-label">Total Bandwidth</div>
                    <div class="stat-value">{{ "%.2f"|format(report.total_bandwidth) }} MB</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-label">Error Rate</div>
                    <div class="stat-value">{{ "%.1f"|format(report.error_rate) }}%</div>
                </div>
            </div>
            
            <!-- Charts Grid -->
            {% if traffic_chart or status_chart %}
            <div class="charts-grid">
                {% if traffic_chart %}
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Traffic Analysis</h3>
                        <p>Request volume over time</p>
                    </div>
                    <div class="chart-body" id="trafficChart"></div>
                </div>
                {% endif %}
                
                {% if status_chart %}
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Status Codes</h3>
                        <p>HTTP response distribution</p>
                    </div>
                    <div class="chart-body" id="statusChart"></div>
                </div>
                {% endif %}
            </div>
            {% endif %}
            
            <!-- Insights Section -->
            <div class="insights-section">
                <div class="insights-card">
                    <div class="insights-header">
                        <h3><i class="fas fa-lightbulb"></i> Key Insights</h3>
                    </div>
                    <div class="insights-body">
                        {% for insight in report.insights %}
                        <div class="insight-item">
                            <div class="insight-icon">
                                <i class="fas fa-info-circle"></i>
                            </div>
                            <div class="insight-content">
                                <div class="insight-description">{{ insight }}</div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
                
                <div class="insights-card">
                    <div class="insights-header" style="background: linear-gradient(135deg, var(--success), #059669);">
                        <h3><i class="fas fa-check-circle"></i> Recommendations</h3>
                    </div>
                    <div class="insights-body">
                        {% for rec in report.recommendations %}
                        <div class="recommendation-item">
                            <div class="recommendation-icon">
                                <i class="fas fa-{% if 'wrench' in rec %}wrench{% elif 'lock' in rec %}lock{% else %}check-circle{% endif %}"></i>
                            </div>
                            <div class="recommendation-text">{{ rec }}</div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <!-- Data Tables -->
            <div class="tables-grid">
                <div class="table-card">
                    <div class="table-header">
                        <h3><i class="fas fa-link"></i> Top Paths</h3>
                    </div>
                    <div class="table-body">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Path</th>
                                    <th>Requests</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for path, count in report.top_paths %}
                                <tr>
                                    <td><code>{{ path }}</code></td>
                                    <td><span class="badge badge-info">{{ count }}</span></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="table-card">
                    <div class="table-header">
                        <h3><i class="fas fa-globe"></i> Top IP Addresses</h3>
                    </div>
                    <div class="table-body">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Requests</th>
                                    <th>Location</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for ip, data in report.top_ips %}
                                <tr>
                                    <td><code>{{ ip }}</code></td>
                                    <td><span class="badge badge-info">{{ data.count }}</span></td>
                                    <td>{{ data.geo.country }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Export Section -->
            <div class="upload-card" style="margin-top: 2rem;">
                <div class="upload-header" style="background: linear-gradient(135deg, var(--success), #059669);">
                    <h2><i class="fas fa-download"></i> Export Report</h2>
                </div>
                <div class="upload-body">
                    <div class="btn-group">
                        <button class="btn btn-primary" onclick="exportReport('json')">
                            <i class="fas fa-file-code"></i>
                            JSON
                        </button>
                        <button class="btn btn-primary" onclick="exportReport('csv')">
                            <i class="fas fa-file-csv"></i>
                            CSV
                        </button>
                    </div>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Footer -->
        <div class="footer">
            <p>CloudLog Pro v3.0 | Enterprise Log Analysis Platform</p>
        </div>
    </div>
    
    <script>
        // File upload handling - FIXED: No double click issue
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const fileInfo = document.getElementById('fileInfo');
        const fileName = document.getElementById('fileName');
        const uploadForm = document.getElementById('uploadForm');
        const submitBtn = document.getElementById('submitBtn');
        const loadingOverlay = document.getElementById('loadingOverlay');
        
        // Remove click event listener - file input is now directly clickable
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--primary)';
            uploadArea.style.background = '#eff6ff';
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'var(--border)';
            uploadArea.style.background = 'var(--light)';
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--border)';
            uploadArea.style.background = 'var(--light)';
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileDisplay(files[0].name);
            }
        });
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                updateFileDisplay(e.target.files[0].name);
            }
        });
        
        function updateFileDisplay(filename) {
            fileName.textContent = filename;
            fileInfo.classList.add('active');
        }
        
        // Form submission
        uploadForm.addEventListener('submit', (e) => {
            if (fileInput.files.length === 0) {
                e.preventDefault();
                alert('Please select a file first');
                return;
            }
            
            loadingOverlay.classList.add('active');
        });
        
        // Auto-hide flash messages
        setTimeout(() => {
            const flashMessages = document.querySelectorAll('.flash-message');
            flashMessages.forEach(msg => {
                msg.style.opacity = '0';
                setTimeout(() => msg.remove(), 300);
            });
        }, 5000);
        
        // Export function
        function exportReport(format) {
            {% if report %}
            const reportId = "{{ report.id }}";
            window.location.href = `/export/${reportId}/${format}`;
            {% endif %}
        }
        
        // Initialize charts
        {% if traffic_chart %}
        const trafficData = {{ traffic_chart|safe }};
        Plotly.newPlot('trafficChart', trafficData.data, trafficData.layout);
        {% endif %}
        
        {% if status_chart %}
        const statusData = {{ status_chart|safe }};
        Plotly.newPlot('statusChart', statusData.data, statusData.layout);
        {% endif %}
    </script>
</body>
</html>
"""

# ============================================================================
# Routes
# ============================================================================

@app.route("/", methods=["GET", "POST"])
def index():
    """Main route for log analysis"""
    report = None
    traffic_chart = None
    status_chart = None
    
    if request.method == "POST":
        try:
            uploaded_file = request.files.get("logfile")
            
            if not uploaded_file or uploaded_file.filename == '':
                flash('Please select a file to analyze', 'error')
                return render_template_string(HTML_TEMPLATE)
            
            # Validate file
            filename = secure_filename(uploaded_file.filename)
            if not allowed_file(filename):
                flash('Invalid file type. Please upload .log, .txt, .csv, or .gz files', 'error')
                return render_template_string(HTML_TEMPLATE)
            
            # Read file content
            file_content = uploaded_file.read()
            
            # Handle gzipped files
            if filename.endswith('.gz'):
                try:
                    file_content = gzip.decompress(file_content)
                except:
                    flash('Error decompressing gzip file', 'error')
                    return render_template_string(HTML_TEMPLATE)
            
            # Decode content
            try:
                content = file_content.decode('utf-8', errors='ignore')
            except:
                content = file_content.decode('latin-1', errors='ignore')
            
            if len(content.strip()) == 0:
                flash('The uploaded file is empty', 'error')
                return render_template_string(HTML_TEMPLATE)
            
            # Parse log entries
            entries = []
            for line_num, line in enumerate(content.splitlines(), 1):
                if line_num > Config.MAX_LINES_PER_FILE:
                    flash(f'File truncated to {Config.MAX_LINES_PER_FILE} lines', 'warning')
                    break
                    
                if line.strip():
                    entry = parser.parse_line(line)
                    if entry:
                        entries.append(entry)
            
            if not entries:
                flash('No valid log entries found in the file', 'warning')
                return render_template_string(HTML_TEMPLATE)
            
            # Analyze entries
            report = analytics.analyze(entries, filename)
            
            # Generate charts
            if PLOTLY_AVAILABLE:
                traffic_chart = viz.create_traffic_chart(report)
                status_chart = viz.create_status_chart(report)
            
            # Cache report
            report_id = report.id
            cache_file = Path(Config.CACHE_FOLDER) / f"{report_id}.json"
            with open(cache_file, 'w') as f:
                json.dump(asdict(report), f, default=str)
            
            flash(f'Successfully analyzed {len(entries)} log entries', 'success')
            logger.info(f"Analysis completed for {filename}: {len(entries)} entries")
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            flash(f'Error analyzing file: {str(e)}', 'error')
    
    return render_template_string(
        HTML_TEMPLATE, 
        report=report,
        traffic_chart=traffic_chart,
        status_chart=status_chart
    )

@app.route("/export/<report_id>/<format>")
def export_report(report_id: str, format: str):
    """Export report in various formats"""
    try:
        # Load cached report
        cache_file = Path(Config.CACHE_FOLDER) / f"{report_id}.json"
        if not cache_file.exists():
            return jsonify({"error": "Report not found"}), 404
        
        with open(cache_file, 'r') as f:
            report_data = json.load(f)
        
        if format == 'json':
            response = make_response(json.dumps(report_data, indent=2))
            response.mimetype = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.json'
            return response
            
        elif format == 'csv':
            # Convert to CSV
            output = StringIO()
            output.write('Metric,Value\n')
            
            # Write basic metrics
            metrics = [
                ('Filename', report_data.get('filename', 'N/A')),
                ('Analysis Date', report_data.get('analysis_date', 'N/A')),
                ('Total Requests', report_data.get('total_requests', 0)),
                ('Unique Visitors', report_data.get('unique_visitors', 0)),
                ('Total Bandwidth (MB)', report_data.get('total_bandwidth', 0)),
                ('Error Rate (%)', report_data.get('error_rate', 0)),
                ('Success Rate (%)', report_data.get('success_rate', 0))
            ]
            
            for metric, value in metrics:
                output.write(f'"{metric}","{value}"\n')
            
            response = make_response(output.getvalue())
            response.mimetype = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.csv'
            return response
        
        else:
            return jsonify({"error": "Unsupported format"}), 400
            
    except Exception as e:
        logger.error(f"Export failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    flash('Page not found', 'error')
    return render_template_string(HTML_TEMPLATE), 404

@app.errorhandler(413)
def too_large_error(error):
    flash('File too large. Maximum size is 50MB', 'error')
    return render_template_string(HTML_TEMPLATE), 413

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}", exc_info=True)
    flash('An internal server error occurred', 'error')
    return render_template_string(HTML_TEMPLATE), 500

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # Print welcome message
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ██╗           ║
    ║  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██║           ║
    ║  ██║     ██║     ██║   ██║██║   ██║██║  ██║██║           ║
    ║  ██║     ██║     ██║   ██║██║   ██║██║  ██║██║           ║ 
    ║  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝███████╗      ║
    ║   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝      ║
    ║                                                          ║
    ║              Enterprise Log Analyzer v1                  ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    
    Features:
    • Multi-format log parsing
    • Advanced analytics
    • Interactive visualizations
    • Export capabilities
    
    Server starting on http://localhost:8080
    """)
    
    # Run app
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 8080)),
        debug=Config.DEBUG,
        threaded=True
    )