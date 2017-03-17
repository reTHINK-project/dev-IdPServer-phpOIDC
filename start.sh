cp /var/www/html/phpOp/dbconf.php.sample /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_USER/"$MYSQL_USER"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_PASSWORD/"$MYSQL_PASSWORD"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_HOST/"$MYSQL_HOST"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_PORT/"$MYSQL_PORT"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_DATABASE/"$MYSQL_DATABASE"/"  /var/www/html/phpOp/dbconf.php

cp /var/www/html/phpOp/dbconf.php /var/www/html/phpRp/dbconf.php

sed -i "s/MYSQL_USER/"$MYSQL_USER"/"  /var/www/html/demo/includes/config.php
sed -i "s/MYSQL_PASSWORD/"$MYSQL_PASSWORD"/"  /var/www/html/demo/includes/config.php
sed -i "s/MYSQL_HOST/"$MYSQL_HOST"/"  /var/www/html/demo/includes/config.php
sed -i "s/MYSQL_USER/"$MYSQL_USER"/"  /var/www/html/demo/demo.sql
sed -i "s/MYSQL_PASSWORD/"$MYSQL_PASSWORD"/"  /var/www/html/demo/demo.sql

grep -v "/VirtualHost"  /etc/apache2/sites-available/000-default.conf > /tmp/$$
cat << EOF >> /tmp/$$
        <Directory /var/www/html>
                Options Indexes FollowSymLinks MultiViews
                AllowOverride All
                Order allow,deny
                allow from all
        </Directory>
</VirtualHost>
EOF

:>/etc/apache2/sites-available/000-default.conf
cat /tmp/$$ >> /etc/apache2/sites-available/000-default.conf
rm /tmp/$$

service apache2 restart

tail -f /dev/null

