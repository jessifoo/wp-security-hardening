#!/bin/bash

# Install WordPress using WP-CLI
docker-compose exec wordpress wp core install \
    --allow-root \
    --url=http://localhost:8080 \
    --title="WordPress Security Test Site" \
    --admin_user=admin \
    --admin_password=admin123 \
    --admin_email=admin@example.com \
    --skip-email

# Activate our plugin
docker-compose exec wordpress wp plugin activate wp-security-hardening --allow-root

echo "WordPress setup complete!"
echo "Admin URL: http://localhost:8080/wp-admin"
echo "Username: admin"
echo "Password: admin123"
