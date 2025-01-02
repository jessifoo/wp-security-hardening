#!/bin/bash

# Fix coding standards
./vendor/bin/phpcbf --standard=WordPress ./includes

# Fix file permissions
chmod +x ./fix-standards.sh
