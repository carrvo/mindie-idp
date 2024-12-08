#!/bin/bash

# SelfAuth
sudo mkdir /var/lib/selfauth
sudo chgrp www-data /var/lib/selfauth/
sudo chmod g+rwx /var/lib/selfauth/
# MinToken
sudo mkdir /var/lib/php-mintoken
sudo chgrp www-data /var/lib/php-mintoken/
sudo chmod g+rx /var/lib/php-mintoken/
sudo sqlite3 /var/lib/php-mintoken/tokens.sqlite3 < ./mintoken/schema.sql
sudo chgrp www-data /var/lib/php-mintoken/tokens.sqlite3
sudo chmod g+rw /var/lib/php-mintoken/tokens.sqlite3
