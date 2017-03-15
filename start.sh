cp /var/www/html/phpOp/dbconf.php.sample /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_USER/"$MYSQL_USER"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_PASSWORD/"$MYSQL_PASSWORD"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_HOST/"$MYSQL_HOST"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_PORT/"$MYSQL_PORT"/"  /var/www/html/phpOp/dbconf.php
sed -i "s/MYSQL_DATABASE/"$MYSQL_DATABASE"/"  /var/www/html/phpOp/dbconf.php

cp /var/www/html/phpOp/dbconf.php /var/www/html/phpRp/dbconf.php

service apache2 restart

tail -f /dev/null

