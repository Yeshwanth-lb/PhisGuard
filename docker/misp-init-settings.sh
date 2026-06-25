#!/bin/bash
# Runs once on every MISP container start via supervisord.
# Waits for MISP to be fully up, then applies settings that would otherwise
# reset to defaults when the container is recreated.

# Wait for nginx + PHP to be ready
for i in $(seq 1 60); do
    if curl -sk "https://localhost/servers/getVersion" -H "Authorization: ${MISP_KEY}" | grep -q "version"; then
        break
    fi
    sleep 2
done

CAKE="/var/www/MISP/app/Console/cake Admin setSetting -q"

# Fix baseurl — must include port 8443 so nav links work correctly in browser
sudo -u www-data $CAKE "MISP.baseurl" "https://localhost:8443"

# Tell PHP the connection is HTTPS — prevents redirect loop
sudo -u www-data $CAKE "Security.force_https" true

# Keep live mode on
sudo -u www-data $CAKE "MISP.live" true

echo "MISP settings applied: baseurl=https://localhost:8443 force_https=true"
