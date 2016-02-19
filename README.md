# dev-IdPServer-phpOIDC
This server is adapted from Nat Sakumura PhPOIDC implementation. A demo application to register a new client and to use the IdP for a client application is provided (folder demo).

## Installation guide
### Dependency/Requirements 
The requirements are the same than the original phpOIDC server (see https://bitbucket.org/PEOFIAMP/phpoidc)  
 * Apache Web Server with SSL  
 * MySQL  
 * PHP 5.3 + PHP Modules:   
  MDB2  
  MDB2_Driver_mysql  
  Doctrine ORM 1.2.4  
  PHPSecLib  

Install mysql and create a database and its user with a password.
<pre><code>
    % sudo apt-get install mysql-server  <br>
    % mysql -p  
    mysql> create database `phpOidc`;  
    mysql> grant all on phpOidc.* to phpOidc identified by 'new_password';  
    mysql> quit;  
</code></pre>
There are two directories/folders: phpOp, and phpRp. They are the source code for OpenID Connect Provider and OpenID Connect Relying Party respecitively. 
Follow the instruction that appears at the end of the installation (Configure apache for SSL if it were not previously.)  
Restart apache.  


