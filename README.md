# NGINX Installation Guide

NGINX is a free and open-source web server, reverse proxy, load balancer, and HTTP cache. Originally written by Igor Sysoev to solve the C10K problem, it's now one of the most popular web servers in the world. NGINX serves as a FOSS alternative to commercial solutions like F5 BIG-IP, Citrix ADC, or proprietary CDNs, offering enterprise-grade performance and reliability without licensing costs.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for high traffic)
  - RAM: 512MB minimum (2GB+ recommended for production)
  - Storage: 100MB for installation (more for logs and cache)
- **Operating System**: Linux, BSD, macOS, or Windows
- **Network Requirements**:
  - Port 80 (HTTP) and/or 443 (HTTPS)
  - Additional ports for specific applications
- **Dependencies**:
  - PCRE library (for regular expressions)
  - zlib library (for gzip compression)
  - OpenSSL library (for SSL/TLS support)
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# RHEL/CentOS 7
sudo yum install -y epel-release
sudo yum install -y nginx

# RHEL/CentOS/Rocky/AlmaLinux 8+
sudo dnf install -y epel-release
sudo dnf install -y nginx

# Official NGINX repository (recommended for latest stable)
sudo tee /etc/yum.repos.d/nginx.repo <<'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF

# Install from official repository
sudo dnf install -y nginx

# Enable and start service
sudo systemctl enable --now nginx
```

### Debian/Ubuntu

```bash
# Distribution packages
sudo apt update
sudo apt install -y nginx

# Official NGINX repository (recommended for latest stable)
# Install prerequisites
sudo apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring

# Add NGINX signing key
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

# Add repository
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list

# Install nginx
sudo apt update
sudo apt install -y nginx

# Enable and start service
sudo systemctl enable --now nginx
```

### Arch Linux

```bash
# Install nginx from official repositories
sudo pacman -S nginx

# Optional: Install additional modules
sudo pacman -S nginx-mod-brotli nginx-mod-headers-more nginx-mod-naxsi

# For GeoIP support
sudo pacman -S nginx-mod-geoip2

# Enable and start service
sudo systemctl enable --now nginx

# Install mainline version from AUR
yay -S nginx-mainline

# Configuration location: /etc/nginx/
```

### Alpine Linux

```bash
# Install nginx
apk add --no-cache nginx

# Install additional modules
apk add --no-cache nginx-mod-http-lua nginx-mod-stream nginx-mod-http-geoip2

# Create required directories
mkdir -p /run/nginx /var/lib/nginx/tmp

# Create nginx user if not exists
adduser -D -H -s /sbin/nologin -G nginx -g nginx nginx

# Enable and start service
rc-update add nginx default
rc-service nginx start

# Configuration location: /etc/nginx/
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y nginx

# Install additional modules
sudo zypper install -y nginx-module-geoip nginx-module-image-filter

# SLES 15
sudo SUSEConnect -p sle-module-web-scripting/15.5/x86_64
sudo zypper install -y nginx

# Enable and start service
sudo systemctl enable --now nginx

# Configuration location: /etc/nginx/
```

### macOS

```bash
# Using Homebrew
brew install nginx

# Start as service
brew services start nginx

# Or run manually
nginx

# Configuration location: /usr/local/etc/nginx/
# Alternative: /opt/homebrew/etc/nginx/ (Apple Silicon)
```

### FreeBSD

```bash
# Using pkg
pkg install nginx

# Enable in rc.conf
echo 'nginx_enable="YES"' >> /etc/rc.conf

# Start service
service nginx start

# Configuration location: /usr/local/etc/nginx/
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install nginx

# Method 2: Using Scoop
scoop install nginx

# Method 3: Manual installation
# Download from http://nginx.org/en/download.html
# Extract to C:\nginx

# Start nginx
cd C:\nginx
start nginx

# Install as Windows service using NSSM
nssm install nginx C:\nginx\nginx.exe
nssm set nginx AppDirectory C:\nginx
nssm start nginx

# Configuration location: C:\nginx\conf\
```

## Initial Configuration

### First-Run Setup

1. **Create nginx user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/cache/nginx -s /sbin/nologin -c "nginx user" nginx
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/nginx/nginx.conf`
- Debian/Ubuntu: `/etc/nginx/nginx.conf`
- Arch Linux: `/etc/nginx/nginx.conf`
- Alpine Linux: `/etc/nginx/nginx.conf`
- openSUSE/SLES: `/etc/nginx/nginx.conf`
- macOS: `/usr/local/etc/nginx/nginx.conf`
- FreeBSD: `/usr/local/etc/nginx/nginx.conf`
- Windows: `C:\nginx\conf\nginx.conf`

3. **Essential settings to change**:

```nginx
# /etc/nginx/nginx.conf
user nginx;  # Run as non-root user
worker_processes auto;  # Auto-detect CPU cores
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;  # Increase for high traffic
    use epoll;  # Linux only, efficient connection method
}

http {
    # Hide nginx version
    server_tokens off;
    
    # Basic security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Remove default server block
    # Create site-specific configs in /etc/nginx/conf.d/
}
```

### Testing Initial Setup

```bash
# Test configuration syntax
sudo nginx -t

# Check nginx version and modules
nginx -V

# Verify nginx is listening
sudo ss -tlnp | grep :80

# Test with curl
curl -I http://localhost
```

**WARNING:** Remove or modify the default server block to prevent information disclosure!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable nginx to start on boot
sudo systemctl enable nginx

# Start nginx
sudo systemctl start nginx

# Stop nginx
sudo systemctl stop nginx

# Restart nginx
sudo systemctl restart nginx

# Reload configuration without downtime
sudo systemctl reload nginx

# Check status
sudo systemctl status nginx

# View logs
sudo journalctl -u nginx -f
```

### OpenRC (Alpine Linux)

```bash
# Enable nginx to start on boot
rc-update add nginx default

# Start nginx
rc-service nginx start

# Stop nginx
rc-service nginx stop

# Restart nginx
rc-service nginx restart

# Reload configuration
rc-service nginx reload

# Check status
rc-service nginx status
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'nginx_enable="YES"' >> /etc/rc.conf

# Start nginx
service nginx start

# Stop nginx
service nginx stop

# Restart nginx
service nginx restart

# Reload configuration
service nginx reload

# Check status
service nginx status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start nginx
brew services stop nginx
brew services restart nginx

# Manual launchd control
sudo launchctl load /Library/LaunchDaemons/homebrew.mxcl.nginx.plist
sudo launchctl unload /Library/LaunchDaemons/homebrew.mxcl.nginx.plist
```

### Windows Service Manager

```powershell
# Using NSSM
nssm start nginx
nssm stop nginx
nssm restart nginx

# Using nginx directly
nginx -s stop
nginx -s quit  # Graceful shutdown
nginx -s reload
nginx -s reopen  # Reopen log files
```

## Advanced Configuration

### Main Configuration Structure

```nginx
# /etc/nginx/nginx.conf
user nginx;
worker_processes auto;
worker_cpu_affinity auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

# Load dynamic modules
load_module modules/ngx_http_geoip2_module.so;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main buffer=16k;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml application/atom+xml image/svg+xml;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Include server blocks
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

### Virtual Host Example

```nginx
# /etc/nginx/conf.d/example.com.conf
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Logging
    access_log /var/log/nginx/example.com.access.log;
    error_log /var/log/nginx/example.com.error.log;

    # Root directory
    root /var/www/example.com/public;
    index index.html index.htm index.php;

    # Locations
    location / {
        try_files $uri $uri/ =404;
    }

    # PHP-FPM configuration
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }
}
```

## Reverse Proxy Setup

### Basic Reverse Proxy

```nginx
# /etc/nginx/conf.d/app.example.com.conf
upstream backend {
    server 127.0.0.1:3000;
    server 127.0.0.1:3001 backup;
    keepalive 32;
}

server {
    listen 80;
    server_name app.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Websocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Load Balancing Methods

```nginx
# Round-robin (default)
upstream backend {
    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com;
}

# Least connections
upstream backend {
    least_conn;
    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com;
}

# IP hash (session persistence)
upstream backend {
    ip_hash;
    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com;
}

# Weighted distribution
upstream backend {
    server backend1.example.com weight=3;
    server backend2.example.com weight=2;
    server backend3.example.com weight=1;
}
```

## Security Configuration

### Basic Security Hardening

```nginx
# Global security settings in nginx.conf
http {
    # Hide nginx version
    server_tokens off;
    
    # Limit request methods
    if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$) {
        return 405;
    }
    
    # Limit buffer sizes
    client_body_buffer_size 1K;
    client_header_buffer_size 1k;
    client_max_body_size 1M;
    large_client_header_buffers 2 1k;
    
    # Timeouts
    client_body_timeout 10;
    client_header_timeout 10;
    keepalive_timeout 5 5;
    send_timeout 10;
    
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=3r/m;
    limit_conn_zone $binary_remote_addr zone=addr:10m;
}
```

### SSL/TLS Best Practices

```nginx
# Modern SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# Enable HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# SSL session caching
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# Diffie-Hellman parameters
ssl_dhparam /etc/nginx/dhparam.pem;
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 'Nginx Full'
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from any to any port {80, 443}
```

### ModSecurity WAF Integration

```bash
# Install ModSecurity
# Debian/Ubuntu
sudo apt install -y libmodsecurity3 libmodsecurity-nginx

# Build nginx with ModSecurity support
./configure --add-dynamic-module=/path/to/ModSecurity-nginx

# Load module in nginx.conf
load_module modules/ngx_http_modsecurity_module.so;

# Enable in server block
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## Database Setup

Not applicable for NGINX as it doesn't require a database. However, NGINX can be configured to work with various database-backed applications through reverse proxy configurations.

## Performance Optimization

### System Tuning

```bash
# /etc/sysctl.conf
# Increase system limits
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0

# File descriptors
fs.file-max = 65535

# Apply changes
sudo sysctl -p
```

### NGINX Optimization

```nginx
# Worker configuration
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 65535;
    use epoll;
    multi_accept on;
}

http {
    # Caching
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # Buffer sizes
    client_body_buffer_size 128k;
    client_max_body_size 10m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 16k;
    output_buffers 1 32k;
    postpone_output 1460;

    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_min_length 1000;
    gzip_disable "msie6";
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/rss+xml
        application/atom+xml
        image/svg+xml;
}
```

### Content Caching

```nginx
# Define cache
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=static_cache:10m max_size=1g inactive=60m use_temp_path=off;

server {
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        proxy_cache static_cache;
        proxy_cache_valid 200 60m;
        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
    }
}
```

## Monitoring

### Built-in Status Module

```nginx
# Enable stub_status
server {
    listen 127.0.0.1:8080;
    server_name localhost;
    
    location /nginx_status {
        stub_status;
        allow 127.0.0.1;
        deny all;
    }
}
```

### Access with curl

```bash
# Get basic metrics
curl http://127.0.0.1:8080/nginx_status

# Sample output:
# Active connections: 291
# server accepts handled requests
#  16630948 16630948 31070465
# Reading: 6 Writing: 179 Waiting: 106
```

### Log Analysis

```bash
# Top 10 IP addresses
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10

# Response codes distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Requests per second
tail -10000 /var/log/nginx/access.log | awk '{print $4}' | uniq -c

# Slow requests (>1s)
awk '$11 > 1' /var/log/nginx/access.log
```

### Prometheus Exporter

```bash
# Install nginx-prometheus-exporter
wget https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v0.11.0/nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz
tar xzf nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz
sudo mv nginx-prometheus-exporter /usr/local/bin/

# Run exporter
nginx-prometheus-exporter -nginx.scrape-uri=http://127.0.0.1:8080/nginx_status

# Add to Prometheus config
scrape_configs:
  - job_name: 'nginx'
    static_configs:
      - targets: ['localhost:9113']
```

## 9. Backup and Restore

### What to Backup

1. **Configuration files**:
```bash
/etc/nginx/nginx.conf
/etc/nginx/conf.d/
/etc/nginx/sites-available/
/etc/nginx/sites-enabled/
/etc/nginx/snippets/
```

2. **SSL certificates**:
```bash
/etc/letsencrypt/
/etc/ssl/certs/
/etc/ssl/private/
```

3. **Log files** (if needed):
```bash
/var/log/nginx/
```

### Backup Script

```bash
#!/bin/bash
# backup-nginx.sh

BACKUP_DIR="/backup/nginx/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup nginx configuration
tar czf "$BACKUP_DIR/nginx-config.tar.gz" \
    /etc/nginx/ \
    --exclude='*.log' \
    --exclude='*.pid'

# Backup SSL certificates
if [ -d /etc/letsencrypt ]; then
    tar czf "$BACKUP_DIR/letsencrypt.tar.gz" /etc/letsencrypt/
fi

# Save package version
nginx -v 2>&1 | tee "$BACKUP_DIR/nginx-version.txt"

# Test configuration backup
tar -tzf "$BACKUP_DIR/nginx-config.tar.gz" > "$BACKUP_DIR/backup-contents.txt"

echo "Backup completed: $BACKUP_DIR"
```

### Restore Script

```bash
#!/bin/bash
# restore-nginx.sh

BACKUP_DIR="$1"
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    exit 1
fi

# Stop nginx
sudo systemctl stop nginx

# Restore configuration
sudo tar xzf "$BACKUP_DIR/nginx-config.tar.gz" -C /

# Restore SSL certificates
if [ -f "$BACKUP_DIR/letsencrypt.tar.gz" ]; then
    sudo tar xzf "$BACKUP_DIR/letsencrypt.tar.gz" -C /
fi

# Test configuration
sudo nginx -t

if [ $? -eq 0 ]; then
    # Start nginx if config is valid
    sudo systemctl start nginx
    echo "Restore completed successfully"
else
    echo "Configuration test failed! Please check the configuration"
    exit 1
fi
```

## 6. Troubleshooting

### Common Issues

1. **Port 80/443 already in use**:
```bash
# Find process using port
sudo ss -tlnp | grep :80
sudo lsof -i :80

# Stop conflicting service (e.g., Apache)
sudo systemctl stop apache2
sudo systemctl disable apache2
```

2. **Permission denied errors**:
```bash
# Check nginx user
ps aux | grep nginx

# Fix ownership
sudo chown -R nginx:nginx /var/cache/nginx
sudo chown -R nginx:nginx /var/log/nginx

# SELinux issues (RHEL/CentOS)
sudo semanage port -l | grep http_port_t
sudo setsebool -P httpd_can_network_connect 1
```

3. **502 Bad Gateway**:
```bash
# Check upstream service
curl -I http://localhost:3000

# Check nginx error log
sudo tail -f /var/log/nginx/error.log

# Verify socket permissions (PHP-FPM example)
ls -la /var/run/php/php8.1-fpm.sock
```

4. **SSL certificate issues**:
```bash
# Test SSL configuration
openssl s_client -connect example.com:443

# Verify certificate
sudo nginx -t

# Check certificate expiry
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -dates
```

### Debug Mode

```nginx
# Enable debug logging
error_log /var/log/nginx/error.log debug;

# Debug specific module
error_log /var/log/nginx/error.log debug_http;

# Debug rewrite rules
rewrite_log on;
error_log /var/log/nginx/rewrite.log notice;
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update nginx
sudo dnf update nginx

# Debian/Ubuntu
sudo apt update
sudo apt upgrade nginx

# Arch Linux
sudo pacman -Syu nginx

# Alpine Linux
apk update
apk upgrade nginx

# openSUSE
sudo zypper update nginx

# FreeBSD
pkg update
pkg upgrade nginx

# Always test configuration after update
sudo nginx -t
sudo systemctl reload nginx
```

### Log Rotation

```bash
# Default logrotate configuration
# /etc/logrotate.d/nginx
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    prerotate
        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
            run-parts /etc/logrotate.d/httpd-prerotate; \
        fi
    endscript
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}
```

### Performance Monitoring

```bash
# Monitor nginx processes
htop -p $(pgrep -d, nginx)

# Check memory usage
ps aux | grep nginx | awk '{sum+=$6} END {print "Total RSS: " sum/1024 " MB"}'

# Monitor connections
watch -n 1 'ss -tan | grep :80 | wc -l'

# Check open files
sudo lsof -u nginx | wc -l
```

## Integration Examples

### PHP-FPM Integration

```nginx
# PHP-FPM upstream
upstream php-fpm {
    server unix:/var/run/php/php8.1-fpm.sock;
}

server {
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass php-fpm;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        
        # Performance
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
    }
}
```

### Node.js Application

```nginx
upstream nodejs_app {
    server 127.0.0.1:3000;
    keepalive 64;
}

server {
    location / {
        proxy_pass http://nodejs_app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Python/Gunicorn Integration

```nginx
upstream gunicorn_app {
    server unix:/run/gunicorn.sock fail_timeout=0;
}

server {
    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        proxy_pass http://gunicorn_app;
    }
    
    location /static/ {
        alias /var/www/app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

### Ruby on Rails

```nginx
upstream rails_app {
    server unix:/var/www/app/shared/sockets/puma.sock fail_timeout=0;
}

server {
    root /var/www/app/current/public;
    
    location / {
        try_files $uri @rails_app;
    }
    
    location @rails_app {
        proxy_pass http://rails_app;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $http_host;
        proxy_redirect off;
    }
    
    location ~ ^/(assets|packs)/ {
        gzip_static on;
        expires max;
        add_header Cache-Control public;
    }
}
```

### WebSocket Support

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

upstream websocket {
    server 127.0.0.1:8080;
}

server {
    location /ws {
        proxy_pass http://websocket;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }
}
```

## Additional Resources

- [Official Documentation](https://nginx.org/en/docs/)
- [GitHub Repository](https://github.com/nginx/nginx)
- [NGINX Wiki](https://www.nginx.com/resources/wiki/)
- [NGINX Config Generator](https://www.digitalocean.com/community/tools/nginx)
- [Community Forum](https://forum.nginx.org/)
- [Security Advisories](https://nginx.org/en/security_advisories.html)
- [Module Registry](https://www.nginx.com/resources/wiki/modules/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.