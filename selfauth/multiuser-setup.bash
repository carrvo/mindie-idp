sudo mkdir /var/lib/selfauth
sudo chgrp www-data /var/lib/selfauth/
sudo chmod g+rwx /var/lib/selfauth/
sudo sqlite3 /var/lib/selfauth/multiuser.sqlite3 < ./schema.sql
sudo chgrp www-data /var/lib/selfauth/multiuser.sqlite3
sudo chmod g+rw /var/lib/selfauth/multiuser.sqlite3
