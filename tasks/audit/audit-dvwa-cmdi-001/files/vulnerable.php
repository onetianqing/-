<?php

function ping_host(array $request): string
{
    $target = $request["ip"] ?? "127.0.0.1";
    $count = $request["count"] ?? "4";
    $cmd = "ping -c " . $count . " " . $target;
    $output = shell_exec($cmd);
    return "<pre>" . htmlspecialchars($output ?? "", ENT_QUOTES, "UTF-8") . "</pre>";
}

echo ping_host($_GET);
