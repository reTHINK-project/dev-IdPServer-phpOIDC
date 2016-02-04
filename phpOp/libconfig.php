<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */




define('OP_DB_CONF_FILE',                   __DIR__ . '/dbconf.php');
define('RP_DB_CONF_FILE',                   dirname(__DIR__)  . '/phpRp/dbconf.php');
define('DB_CONF_TEMPLATE',                  __DIR__ . '/dbconf.php.sample');
define('AB_CONF_TEMPLATE',                   __DIR__ . '/abconstants.php.sample');
define('OP_AB_CONF_FILE',                   __DIR__ . '/abconstants.php');
define('RP_AB_CONF_FILE',                   dirname(__DIR__)  . '/phpRp/abconstants.php');


function configureDB($template, $configFile, $host, $port, $db, $user, $password, &$replacedText = null) {
    $config = file_get_contents($template);
    if(!is_null($replacedText))
        $replacedText = '';
    if(isset($config)) {
        $pattern = array(
            '/MYSQL_HOST/',
            '/MYSQL_PORT/',
            '/MYSQL_DATABASE/',
            '/MYSQL_USER/',
            '/MYSQL_PASSWORD/',
            '/MYSQL_HOST/'
        );

        $replacement = array(
            $host,
            $port,
            $db,
            $user,
            $password
        );

        $config = preg_replace($pattern, $replacement, $config);
        if(!is_null($replacedText))
            $replacedText = $config;
        return file_put_contents($configFile, $config);
    }
    return false;
}


function configureAb($template, $configFile, $op_sig_kid, $op_enc_kid, $rp_sig_kid, $rp_enc_kid, &$replacedText = null) {
    $config = file_get_contents($template);
    if(!is_null($replacedText))
        $replacedText = '';
    if(isset($config)) {
        $pattern = array(
            '/CONFIG_OP_SIG_KID/',
            '/CONFIG_OP_ENC_KID/',
            '/CONFIG_RP_SIG_KID/',
            '/CONFIG_RP_ENC_KID/'
        );

        $replacement = array(
            $op_sig_kid,
            $op_enc_kid,
            $rp_sig_kid,
            $rp_enc_kid
        );

        $config = preg_replace($pattern, $replacement, $config);
        if(!is_null($replacedText))
            $replacedText = $config;
        return file_put_contents($configFile, $config);
    }
    return false;
}


function checkDbConf() {
    if(!file_exists(OP_DB_CONF_FILE))
        return true;
    else
        return false;
}


function checkDbConnection()
{
    require_once('libdb.php');
    try {
        $db_connection = Doctrine_Manager::connection();
        if(!$db_connection->connect())
            die(1);
    }
    catch(Doctrine_Connection_Exception $e) {
        die(1);
    }
}

// run from commandline
if(isset($argv) && isset($argv[0]) && (basename($argv[0]) == basename(__FILE__))) {
    if($argc >= 2) {
        list($executable, $command) = $argv;
        $executable = array_shift($argv);
        $command = array_shift($argv);

        switch($command) {
            case 'checkdbconnection' :
                checkDbConnection();
                break;
            case 'configAb' :
                list($op_sig_kid, $op_enc_kid, $rp_sig_kid, $rp_enc_kid) = $argv;
                configureAb(AB_CONF_TEMPLATE, OP_AB_CONF_FILE, $op_sig_kid, $op_enc_kid, $rp_sig_kid, $rp_enc_kid);
                copy(OP_AB_CONF_FILE, RP_AB_CONF_FILE);
                break;
            case 'configDb' :
                list($db_host, $db_port, $db_name, $db_user, $db_password) = $argv;

                configureDB(DB_CONF_TEMPLATE, OP_DB_CONF_FILE, $db_host, $db_port, $db_name, $db_user, $db_password);
                copy(OP_DB_CONF_FILE, RP_DB_CONF_FILE);
                if(file_exists(OP_DB_CONF_FILE)) {
                    require_once('migration.php');
                    migrate_db();
                }
                break;
            case 'migrateDb' :
                if(file_exists(OP_DB_CONF_FILE)) {
                    require_once('migration.php');
                    migrate_db();
                }
                break;
            default:
        }
    }
}