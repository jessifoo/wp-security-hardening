#!/bin/bash

# Install PHP dependencies
composer install

# Install PHP CodeSniffer with WordPress standards
composer require --dev wp-coding-standards/wpcs
composer require --dev dealerdirect/phpcodesniffer-composer-installer

# Set up PHPCS
./vendor/bin/phpcs --config-set installed_paths vendor/wp-coding-standards/wpcs
./vendor/bin/phpcs --config-set default_standard WordPress

# Install other development tools
composer require --dev phpunit/phpunit
composer require --dev vimeo/psalm
composer require --dev phpmd/phpmd

# Function to check if containers are running
check_containers() {
    if docker-compose ps | grep -q "wordpress"; then
        return 0
    else
        return 1
    fi
}

# Function to start containers
start_containers() {
    echo "Starting WordPress environment..."
    docker-compose up -d

    # Wait for containers to be ready
    echo "Waiting for containers to be ready..."
    sleep 10

    # Check if WordPress is accessible
    while ! curl -s http://localhost:8080 > /dev/null; do
        echo "Waiting for WordPress to be accessible..."
        sleep 5
    done
}

# Function to stop containers
stop_containers() {
    echo "Stopping WordPress environment..."
    docker-compose down
}

# Main script
case "$1" in
    start)
        if check_containers; then
            echo "WordPress environment is already running"
        else
            start_containers
            echo "WordPress is now running at http://localhost:8080"
            echo "Admin panel is at http://localhost:8080/wp-admin"
            echo "Default credentials:"
            echo "Username: admin"
            echo "Password: password"
        fi
        ;;
    stop)
        if check_containers; then
            stop_containers
            echo "WordPress environment stopped"
        else
            echo "WordPress environment is not running"
        fi
        ;;
    restart)
        if check_containers; then
            stop_containers
        fi
        start_containers
        echo "WordPress environment restarted"
        ;;
    status)
        if check_containers; then
            echo "WordPress environment is running"
            echo "Access it at http://localhost:8080"
        else
            echo "WordPress environment is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
