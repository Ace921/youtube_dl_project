from flask import Flask, request, jsonify, send_file, render_template_string
from yt_dlp import YoutubeDL
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
from concurrent.futures import ThreadPoolExecutor
import uuid
import time
import json
from functools import lru_cache
import re
import hashlib
from apscheduler.schedulers.background import BackgroundScheduler
import psutil  # For system resource monitoring

# Initialize Flask app and enable CORS
app = Flask(__name__)
CORS(app)

# Set app start time at initialization
app.start_time = time.time()

# Set up rate limiting with tiered approach
limiter = Limiter(
    key_func=get_remote_address, 
    default_limits=["20 per minute", "200 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# Configure logging with rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Define download directory with environment variable support
DOWNLOAD_DIR = os.environ.get('DOWNLOAD_DIR', 
                            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads'))
if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR)
    logger.info(f"Created download directory at: {DOWNLOAD_DIR}")

# Set maximum disk usage (default 5GB)
MAX_DISK_USAGE = int(os.environ.get('MAX_DISK_USAGE', 5 * 1024 * 1024 * 1024))  # 5GB in bytes

# Thread pool for concurrent downloads with adaptive sizing
MAX_WORKERS = min(os.cpu_count() * 2, 8)  # Scale with CPU cores but cap at 8
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
logger.info(f"Thread pool initialized with {MAX_WORKERS} workers")

# Track active downloads
active_downloads = {}
download_stats = {
    "total_downloads": 0,
    "successful_downloads": 0,
    "failed_downloads": 0,
    "total_bytes_downloaded": 0
}

# URL validation patterns
YOUTUBE_PATTERN = r'^(https?://)?(www\.)?(youtube\.com|youtu\.be)/'
GENERAL_URL_PATTERN = r'^(https?:\/\/)?(www\.)?[a-zA-Z0-9\-\.]+\.[a-z]{2,}\/\S*$'

def is_valid_url(url):
    """Validate the URL with stricter regex."""
    if not url:
        return False
    return bool(re.match(GENERAL_URL_PATTERN, url))

def is_youtube_url(url):
    """Check if URL is from YouTube."""
    if not url:
        return False
    return bool(re.match(YOUTUBE_PATTERN, url))

def get_cache_key(url):
    """Create consistent cache key for URL."""
    return hashlib.md5(url.encode()).hexdigest()

@lru_cache(maxsize=200)
def get_video_info(video_url):
    """
    Extract video information without downloading.
    Uses cached results when available.
    """
    cache_key = get_cache_key(video_url)
    logger.info(f"Fetching info for URL (cache key: {cache_key})")
    
    ydl_opts = {
        'quiet': True,
        'skip_download': True,
        'ignoreerrors': False,  # Don't ignore errors for better feedback
    }
    
    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(video_url, download=False)
            return info
    except Exception as e:
        logger.error(f"Error extracting video info: {e}")
        raise

def get_disk_usage(path=DOWNLOAD_DIR):
    """Get current disk usage of the downloads directory."""
    total_size = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total_size += os.path.getsize(fp)
    return total_size

def check_disk_space():
    """Check if there's enough disk space for downloads."""
    if get_disk_usage() > MAX_DISK_USAGE:
        logger.warning(f"Disk usage exceeded limit of {MAX_DISK_USAGE} bytes")
        # Force cleanup of old files
        clean_old_downloads(aggressive=True)
        return get_disk_usage() < MAX_DISK_USAGE
    return True
        
def download_video_from_url(video_url, download_id, format_selection='mp4'):
    """Downloads the video from the given URL using yt-dlp."""
    # First check disk space
    if not check_disk_space():
        raise Exception("Insufficient disk space for download")
        
    # Generate a unique filename based on video ID and timestamp
    unique_id = f"{uuid.uuid4().hex}-{int(time.time())}"
    filename = f"{unique_id}.{format_selection}"
    file_path = os.path.join(DOWNLOAD_DIR, filename)

    # Configure yt-dlp options with performance tuning
    ydl_opts = {
        'format': format_selection,
        'concurrent_fragment_downloads': 10,
        'outtmpl': file_path,
        'retries': 10,
        'fragment_retries': 10,
        'file_access_retries': 5,
        'extractor_retries': 5,
        'buffersize': 1024 * 32,  # Increased buffer size (32KB)
        'progress_hooks': [lambda d: update_progress(d, download_id)],
        'no_warnings': True,
    }
    
    try:
        active_downloads[download_id] = {
            'status': 'downloading',
            'progress': 0,
            'file_path': None,
            'video_url': video_url,
            'error': None,
            'format': format_selection,
            'started_at': time.time(),
            'updated_at': time.time()
        }
        
        logger.info(f"Starting download ID {download_id} for: {video_url}")
        download_stats["total_downloads"] += 1
        
        with YoutubeDL(ydl_opts) as ydl:
            info_dict = ydl.extract_info(video_url, download=True)
        
        # Get file size
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        download_stats["total_bytes_downloaded"] += file_size
        
        active_downloads[download_id].update({
            'status': 'completed',
            'progress': 100,
            'file_path': file_path,
            'title': info_dict.get('title', 'Unknown'),
            'thumbnail': info_dict.get('thumbnail'),
            'duration': info_dict.get('duration'),
            'file_size': file_size,
            'completed_at': time.time(),
            'updated_at': time.time()
        })
        
        download_stats["successful_downloads"] += 1
        logger.info(f"Download completed for ID {download_id}: {info_dict.get('title')}")
        return info_dict, file_path
        
    except Exception as e:
        logger.error(f"Error downloading video (ID: {download_id}): {str(e)}")
        active_downloads[download_id].update({
            'status': 'failed',
            'error': str(e),
            'completed_at': time.time(),
            'updated_at': time.time()
        })
        download_stats["failed_downloads"] += 1
        raise

def update_progress(d, download_id):
    """Update download progress information with rate limiting."""
    # Skip if download not found
    if download_id not in active_downloads:
        return
        
    # Only update progress if it's been at least 0.5 seconds since last update
    current_time = time.time()
    last_update = active_downloads[download_id].get('updated_at', 0)
    
    if current_time - last_update < 0.5:
        return  # Skip this update to reduce CPU usage from frequent updates
        
    if d['status'] == 'downloading' and 'downloaded_bytes' in d and 'total_bytes' in d and d['total_bytes']:
        progress = (d['downloaded_bytes'] / d['total_bytes']) * 100
        active_downloads[download_id]['progress'] = round(progress, 2)
        
        # Add download speed and ETA if available
        if 'speed' in d:
            active_downloads[download_id]['speed'] = d['speed']
        if 'eta' in d:
            active_downloads[download_id]['eta'] = d['eta']
            
        active_downloads[download_id]['updated_at'] = current_time
            
    elif d['status'] == 'finished':
        active_downloads[download_id]['progress'] = 100
        active_downloads[download_id]['updated_at'] = current_time

def clean_old_downloads(aggressive=False):
    """
    Clean old downloaded files to prevent disk fill-up.
    If aggressive=True, will remove more files to free up space.
    """
    current_time = time.time()
    removed_count = 0
    freed_bytes = 0
    
    # First, clean up completed downloads older than 1 hour
    retention_period = 1800 if aggressive else 3600  # 30 min in aggressive mode, 1 hour normal
    
    for download_id, download_info in list(active_downloads.items()):
        # Remove completed downloads after retention period
        if (download_info.get('status') in ['completed', 'cancelled', 'failed'] and 
            download_info.get('completed_at', 0) < current_time - retention_period):
            
            file_path = download_info.get('file_path')
            if file_path and os.path.exists(file_path):
                try:
                    file_size = os.path.getsize(file_path)
                    os.remove(file_path)
                    logger.info(f"Removed old download file: {file_path}")
                    removed_count += 1
                    freed_bytes += file_size
                except Exception as e:
                    logger.error(f"Failed to remove old file: {e}")
            
            # Remove from tracking dictionary
            active_downloads.pop(download_id, None)
    
    # Second, clean up stalled downloads (no progress for 10+ minutes)
    stall_timeout = 300 if aggressive else 600  # 5 min in aggressive mode, 10 min normal
    
    for download_id, download_info in list(active_downloads.items()):
        if (download_info.get('status') == 'downloading' and 
            download_info.get('updated_at', 0) < current_time - stall_timeout):
            
            file_path = download_info.get('file_path')
            if file_path and os.path.exists(file_path):
                try:
                    file_size = os.path.getsize(file_path)
                    os.remove(file_path)
                    logger.info(f"Removed stalled download file: {file_path}")
                    removed_count += 1
                    freed_bytes += file_size
                except Exception as e:
                    logger.error(f"Failed to remove stalled file: {e}")
            
            # Mark as failed
            active_downloads[download_id].update({
                'status': 'failed',
                'error': 'Download stalled and was automatically cancelled',
                'completed_at': current_time
            })
    
    logger.info(f"Cleanup finished: removed {removed_count} files, freed {freed_bytes} bytes")
    return {"removed_files": removed_count, "freed_bytes": freed_bytes}

def monitor_system_resources():
    """Monitor and log system resource usage."""
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    
    logger.info(f"System monitor: CPU {cpu_percent}%, Memory {memory.percent}%")
    
    # If resources are critically low, cancel some ongoing downloads
    if cpu_percent > 90 or memory.percent > 90:
        logger.warning("System resources critical, pausing some downloads")
        # Find downloads in progress and cancel oldest ones first
        ongoing = [(id, info) for id, info in active_downloads.items() 
                  if info.get('status') == 'downloading']
        
        if ongoing:
            # Sort by start time (oldest first)
            ongoing.sort(key=lambda x: x[1].get('started_at', 0))
            # Cancel up to half of ongoing downloads
            for id, _ in ongoing[:max(1, len(ongoing)//2)]:
                active_downloads[id].update({
                    'status': 'cancelled',
                    'error': 'Cancelled due to system resource constraints',
                    'completed_at': time.time()
                })
                logger.info(f"Cancelled download {id} due to resource constraints")

# HTML template for simple status page
STATUS_PAGE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>YouTube Downloader API Status</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }
        .stat-box {
            background-color: #f5f5f5;
            border-radius: 4px;
            padding: 15px;
            flex: 1;
            min-width: 200px;
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #0066cc;
        }
    </style>
</head>
<body>
    <h1>YouTube Downloader API Status</h1>
    
    <div class="card">
        <h2>System Status</h2>
        <div class="stats">
            <div class="stat-box">
                <div>CPU Usage</div>
                <div class="stat-value">{{ cpu_percent }}%</div>
            </div>
            <div class="stat-box">
                <div>Memory Usage</div>
                <div class="stat-value">{{ memory_percent }}%</div>
            </div>
            <div class="stat-box">
                <div>Disk Usage</div>
                <div class="stat-value">{{ disk_usage_mb }} MB</div>
            </div>
            <div class="stat-box">
                <div>Active Downloads</div>
                <div class="stat-value">{{ active_count }}</div>
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>Download Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <div>Total Downloads</div>
                <div class="stat-value">{{ stats.total_downloads }}</div>
            </div>
            <div class="stat-box">
                <div>Successful</div>
                <div class="stat-value">{{ stats.successful_downloads }}</div>
            </div>
            <div class="stat-box">
                <div>Failed</div>
                <div class="stat-value">{{ stats.failed_downloads }}</div>
            </div>
            <div class="stat-box">
                <div>Total Data</div>
                <div class="stat-value">{{ total_data }}</div>
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>API Endpoints</h2>
        <ul>
            <li><strong>POST /download</strong> - Start a new download</li>
            <li><strong>GET /info</strong> - Get video information</li>
            <li><strong>GET /status/{id}</strong> - Check download status</li>
            <li><strong>GET /download/{id}</strong> - Download completed file</li>
            <li><strong>POST /cancel/{id}</strong> - Cancel a download</li>
        </ul>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    """Status page with system information."""
    # Gather system info
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk_usage = get_disk_usage() / (1024 * 1024)  # Convert to MB
    
    active_count = sum(1 for info in active_downloads.values() 
                    if info.get('status') == 'downloading')
                    
    # Format total data downloaded
    total_bytes = download_stats["total_bytes_downloaded"]
    if total_bytes > 1073741824:  # 1 GB
        total_data = f"{total_bytes / 1073741824:.2f} GB"
    else:
        total_data = f"{total_bytes / 1048576:.2f} MB"
        
    return render_template_string(STATUS_PAGE_TEMPLATE, 
                                 cpu_percent=cpu_percent,
                                 memory_percent=memory.percent,
                                 disk_usage_mb=round(disk_usage, 2),
                                 active_count=active_count,
                                 stats=download_stats,
                                 total_data=total_data)

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent
    disk_usage = get_disk_usage()
    disk_percent = (disk_usage / MAX_DISK_USAGE) * 100
    
    health_status = "healthy"
    if cpu_percent > 90 or memory_percent > 90 or disk_percent > 90:
        health_status = "degraded"
    
    return jsonify({
        "status": health_status,
        "cpu": cpu_percent,
        "memory": memory_percent,
        "disk": {
            "usage_bytes": disk_usage,
            "usage_percent": disk_percent,
            "max_bytes": MAX_DISK_USAGE
        },
        "downloads": {
            "active": sum(1 for info in active_downloads.values() if info.get('status') == 'downloading'),
            "total": len(active_downloads)
        },
        "uptime": time.time() - app.start_time if hasattr(app, 'start_time') else 0
    }), 200

@app.route('/info', methods=['GET'])
@limiter.limit("10 per minute")
def get_video_info_endpoint():
    """Endpoint to get video info without downloading."""
    video_url = request.args.get('url')
    
    if not video_url or not is_valid_url(video_url):
        return jsonify({"error": "No valid URL provided"}), 400
    
    # For YouTube URLs we'll extract detailed info
    youtube_mode = is_youtube_url(video_url)
    
    try:
        info = get_video_info(video_url)
        if not info:
            return jsonify({"error": "Could not extract video information"}), 404
            
        # Basic response for any URL
        response = {
            "title": info.get('title'),
            "duration": info.get('duration'),
            "extractor": info.get('extractor'),
            "url": video_url,
        }
        
        # Add more details for YouTube
        if youtube_mode:
            response.update({
                "thumbnail": info.get('thumbnail'),
                "uploader": info.get('uploader'),
                "view_count": info.get('view_count'),
                "upload_date": info.get('upload_date'),
                "formats": [
                    {
                        "format_id": f.get('format_id'), 
                        "ext": f.get('ext'),
                        "resolution": f"{f.get('width', 'unknown')}x{f.get('height', 'unknown')}",
                        "filesize": f.get('filesize')
                    } for f in info.get('formats', []) 
                    if f.get('ext') in ['mp4', 'webm', 'mp3'] and f.get('filesize')
                ]
            })
            
        return jsonify(response), 200
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"Error fetching video info: {error_message}")
        
        # Provide more specific error messages
        if "not a valid URL" in error_message.lower():
            return jsonify({"error": "Not a valid or supported URL"}), 400
        elif "unavailable" in error_message.lower():
            return jsonify({"error": "Video is unavailable or restricted"}), 404
        else:
            return jsonify({"error": error_message}), 500

@app.route('/download', methods=['POST'])
@limiter.limit("5 per minute")
def download_video_endpoint():
    """Start a new download asynchronously."""
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
            video_url = data.get('url')
            format_selection = data.get('format', 'mp4')
        else:
            video_url = request.form.get('url')
            format_selection = request.form.get('format', 'mp4')
        
        if not video_url or not is_valid_url(video_url):
            return jsonify({"error": "No valid URL provided"}), 400
            
        # Check if we have disk space first
        if not check_disk_space():
            return jsonify({"error": "Insufficient disk space"}), 507  # 507 Insufficient Storage
        
        # Validate format
        if format_selection not in ['mp4', 'webm', 'mp3', 'best']:
            return jsonify({"error": "Unsupported format"}), 400
        
        # Generate a unique ID for this download
        download_id = str(uuid.uuid4())
        
        # Start download in background thread
        executor.submit(download_video_from_url, video_url, download_id, format_selection)
        
        return jsonify({
            "download_id": download_id,
            "status": "started",
            "message": "Download started. Check status with /status/{download_id}"
        }), 202  # Return 202 Accepted as it's processing
        
    except Exception as e:
        logger.error(f"Error initiating download: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/status/<download_id>', methods=['GET'])
def check_download_status(download_id):
    """Check the status of a download."""
    if download_id not in active_downloads:
        return jsonify({"error": "Download ID not found"}), 404
    
    download_info = active_downloads[download_id].copy()
    
    # Add estimated time remaining if available
    if download_info.get('status') == 'downloading' and download_info.get('eta'):
        download_info['estimated_time_remaining'] = download_info['eta']
        
    # Add formatted file size if available
    if download_info.get('file_size'):
        size_bytes = download_info['file_size']
        if size_bytes > 1073741824:  # 1 GB
            download_info['file_size_formatted'] = f"{size_bytes / 1073741824:.2f} GB"
        else:
            download_info['file_size_formatted'] = f"{size_bytes / 1048576:.2f} MB"
    
    return jsonify(download_info), 200

@app.route('/download/<download_id>', methods=['GET'])
def serve_downloaded_file(download_id):
    """Serve the downloaded file."""
    if download_id not in active_downloads:
        return jsonify({"error": "Download ID not found"}), 404
    
    download_info = active_downloads[download_id]
    if download_info['status'] != 'completed':
        return jsonify({
            "error": "Download not yet completed", 
            "status": download_info['status'],
            "progress": download_info.get('progress', 0)
        }), 400
    
    file_path = download_info['file_path']
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    # Extract original filename or use the title with extension
    original_title = download_info.get('title', 'download')
    # Clean the title for use as filename
    safe_title = re.sub(r'[^\w\s-]', '', original_title).strip().replace(' ', '_')
    extension = os.path.splitext(file_path)[1]
    download_name = f"{safe_title}{extension}"
    
    # Set attachment filename
    return send_file(
        file_path, 
        as_attachment=True, 
        download_name=download_name,
        mimetype='application/octet-stream'
    )

@app.route('/cancel/<download_id>', methods=['POST'])
def cancel_download(download_id):
    """Cancel an in-progress download."""
    if download_id not in active_downloads:
        return jsonify({"error": "Download ID not found"}), 404
    
    download_info = active_downloads[download_id]
    
    # Only cancel if it's still downloading
    if download_info['status'] != 'downloading':
        return jsonify({
            "error": "Download cannot be cancelled", 
            "status": download_info['status']
        }), 400
    
    active_downloads[download_id]['status'] = 'cancelled'
    active_downloads[download_id]['completed_at'] = time.time()
    
    # Try to remove partial file
    file_path = download_info.get('file_path')
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"Removed cancelled download file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to remove cancelled file: {e}")
    
    return jsonify({"status": "cancelled"}), 200

@app.route('/cleanup', methods=['POST'])
@limiter.limit("2 per minute")
def cleanup_downloads():
    """Manual trigger for cleanup process."""
    aggressive = request.args.get('aggressive', '').lower() == 'true'
    result = clean_old_downloads(aggressive=aggressive)
    return jsonify({
        "status": "cleanup completed",
        "removed_files": result["removed_files"],
        "freed_bytes": result["freed_bytes"],
        "disk_usage": get_disk_usage()
    }), 200

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get download statistics."""
    # Count downloads by status
    status_counts = {
        "downloading": 0,
        "completed": 0,
        "failed": 0, 
        "cancelled": 0
    }
    
    for info in active_downloads.values():
        status = info.get('status')
        if status in status_counts:
            status_counts[status] += 1
    
    # Calculate total disk usage
    disk_usage = get_disk_usage()
    disk_limit_percent = (disk_usage / MAX_DISK_USAGE) * 100
    
    # System stats
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    
    return jsonify({
        "download_stats": download_stats,
        "status_counts": status_counts, 
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "disk_usage_bytes": disk_usage,
            "disk_usage_percent": round(disk_limit_percent, 2),
            "thread_pool_size": MAX_WORKERS
        }
    }), 200

# Set up all scheduled tasks
scheduler = BackgroundScheduler()
scheduler.add_job(clean_old_downloads, 'interval', minutes=15)
scheduler.add_job(monitor_system_resources, 'interval', minutes=5)
scheduler.start()

# Make sure scheduler shuts down properly
import atexit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)), debug=False, threaded=True)