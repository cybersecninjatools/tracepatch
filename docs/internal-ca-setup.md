# Setting Up TracePatch with Your Internal Certificate Authority

TracePatch itself has no opinion about TLS -- certificate handling happens
entirely at the reverse proxy (Nginx) in front of the app, not in the
application code. This means bringing your own internal CA-issued
certificate is straightforward and doesn't require any changes to
TracePatch itself.

## Overview

1. TracePatch (Docker container) listens on an internal port (e.g. 5000)
2. Nginx sits in front, terminates TLS using your certificate, and proxies
   requests to the container
3. Your internal CA issues the certificate for your internal hostname
   (e.g. sectrack.yourcompany.internal)

## Steps

### 1. Obtain a certificate from your internal CA

Work with your PKI/AD CS administrator to issue a certificate for the
hostname you'll use. You'll need the certificate file (.crt or .pem) and
the private key file (.key).

### 2. Install Nginx on your host

    apt install -y nginx

### 3. Place your certificate files

    mkdir -p /etc/nginx/ssl
    (copy your cert and key into /etc/nginx/ssl/)

### 4. Configure Nginx as a reverse proxy

Create /etc/nginx/sites-available/tracepatch with contents like:

    server {
        listen 443 ssl;
        server_name sectrack.yourcompany.internal;
        ssl_certificate     /etc/nginx/ssl/your-cert.crt;
        ssl_certificate_key /etc/nginx/ssl/your-key.key;
        location / {
            proxy_pass http://127.0.0.1:5000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }
    }

Then enable it:

    ln -s /etc/nginx/sites-available/tracepatch /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl reload nginx

### 5. Bind the Docker container to localhost only

In your .env file, set:

    SECTRACK_PORT_BIND=127.0.0.1:5000

This ensures the app is only reachable through Nginx, not directly on its
internal port.

### 6. Point internal DNS at this host

Add an internal DNS record for your chosen hostname pointing to this
server's internal IP address.

## Notes

- TracePatch doesn't need to know its own hostname or scheme -- that's
  handled entirely by Nginx and your network.
- Certificate renewal is your organization's responsibility.
- If your organization uses Active Directory Certificate Services (AD CS),
  your PKI administrator can typically auto-enroll a certificate through
  Group Policy, or issue one manually via the certificate templates console.

## Troubleshooting

**Nginx shows as running but the port isn't actually reachable:** check with
`sudo ss -tlnp` to confirm Nginx is genuinely listening on the port you
configured. If it's not, check `/var/log/nginx/error.log` for a line like
"using inherited sockets" — this indicates a stale process/socket state,
usually left over from a prior config change or reload. Force a clean
restart:

    sudo systemctl stop nginx
    sudo pkill -9 -f nginx
    sudo rm -f /run/nginx.pid
    sudo systemctl start nginx

Then re-check with `ss -tlnp` to confirm the port is now bound.

**Using a bare IP address instead of a hostname:** the examples above use
a placeholder hostname (`sectrack.yourcompany.internal`). You can use a
bare IP address (e.g. `server_name 10.0.0.5;`) for quick testing, but a
real internal hostname is strongly recommended for production — it's more
stable if the server's IP ever changes, and it's required if you want your
internal CA to issue a properly-scoped certificate rather than one tied to
a specific IP address.
