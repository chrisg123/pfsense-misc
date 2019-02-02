#!/usr/local/bin/php-cgi -q
<?php
/*
 * filterparser.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2009-2018 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * Originally based on m0n0wall (http://m0n0.ch/wall)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * A quick CLI log parser.
 * Examples:
 *  clog /var/log/filter.log | tail -50 | /usr/local/www/filterparser.php
 *  clog -f /var/log/filter.log | /usr/local/www/filterparser.php
 */

include_once("functions.inc");
include_once("filter_log.inc");

$log = fopen("php://stdin", "r");
$lastline = "";

while (!feof($log)) {
    $line = fgets($log);
    $line = rtrim($line);
    $flent = parse_firewall_log_line(trim($line));
    if ($flent != "") {
        $flags = (($flent['proto'] == "TCP") && !empty($flent['tcpflags'])) ? ":" . $flent['tcpflags'] : "";
        //echo "{$flent['time']} {$flent['act']} {$flent['realint']} {$flent['proto']}{$flags} {$flent['src']} {$flent['dst']}\n";

        // Start: Customized filter parsing
        $actColor = ($flent['act'] == "block") ? ":" . "31m" : "32m";
        $directionFmt = ($flent['direction'] == "in") ? "1;" : "";

        $src = gethostbyaddr($flent['srcip']);
        $dst = gethostbyaddr($flent['dstip']);
        $direction = ($flent['direction'] == "out") ? "--> " : "<-- ";
        usleep(750000); // slow it down for human readability
        echo "\033[1;30m{$flent['time']}\033[m" .
             "\033[1;{$actColor} " . str_pad($flent['act'], 6) . "\033[m" .
             "\033[{$directionFmt}35m{$direction}\033[m" .
             " " . str_pad($flent['interface'], 10) .
             " \033[1;30m{$src}:{$flent['srcport']}\033[m" .
             " \033[1;34m{$flent['proto']}\033[m{$flags} \033[1;30m{$dst}:{$flent['dstport']}\033[m\n";

        // END: Customized filter parsing

        $flent = "";
    }
}
fclose($log); ?>
