rule WordPress_Common_Webshell {
    meta:
        description = "Detect common PHP webshells"
        severity = "critical"
    strings:
        $shell1 = "<?php" nocase
        $shell2 = "eval" nocase
        $shell3 = "base64_decode" nocase
        $shell4 = "system" nocase
        $shell5 = "exec" nocase
        $shell6 = "shell_exec" nocase
        $shell7 = "passthru" nocase
        $shell8 = "proc_open" nocase
        $shell9 = "popen" nocase
        $shell10 = "$_POST" nocase
        $shell11 = "$_GET" nocase
        $shell12 = "$_REQUEST" nocase
        $shell13 = "assert" nocase
    condition:
        $shell1 and (3 of ($shell2,$shell3,$shell4,$shell5,$shell6,$shell7,$shell8,$shell9)) and (1 of ($shell10,$shell11,$shell12))
}

rule WordPress_Backdoor_Upload {
    meta:
        description = "Detect file upload backdoors"
        severity = "critical"
    strings:
        $upload1 = "move_uploaded_file" nocase
        $upload2 = "$_FILES" nocase
        $upload3 = "tmp_name" nocase
        $upload4 = "type=" nocase
        $upload5 = "multipart/form-data" nocase
        $upload6 = "upload" nocase
        $upload7 = "file" nocase
    condition:
        4 of them
}

rule WordPress_Config_Manipulation {
    meta:
        description = "Detect wp-config.php manipulation attempts"
        severity = "critical"
    strings:
        $config1 = "DB_NAME" nocase
        $config2 = "DB_USER" nocase
        $config3 = "DB_PASSWORD" nocase
        $config4 = "DB_HOST" nocase
        $config5 = "define" nocase
        $config6 = "wp_options" nocase
        $config7 = "siteurl" nocase
        $malicious1 = "eval" nocase
        $malicious2 = "base64_decode" nocase
        $malicious3 = "system" nocase
        $malicious4 = "exec" nocase
    condition:
        3 of ($config*) and 1 of ($malicious*)
}

rule WordPress_Malicious_Plugin {
    meta:
        description = "Detect potentially malicious plugins"
        severity = "high"
    strings:
        $plugin1 = "Plugin Name:" nocase
        $plugin2 = "add_action" nocase
        $plugin3 = "add_filter" nocase
        $malicious1 = "eval(" nocase
        $malicious2 = "base64_decode(" nocase
        $malicious3 = "create_function(" nocase
        $malicious4 = "str_rot13(" nocase
        $malicious5 = "gzinflate(" nocase
        $malicious6 = "\\x[0-9a-fA-F]{2}"
        $suspicious1 = "wp_remote_post" nocase
        $suspicious2 = "wp_remote_get" nocase
        $suspicious3 = "curl_exec" nocase
        $obfuscated1 = /(\$[a-zA-Z_0-9]{1,}\[\d+\]\.?){10,}/
        $obfuscated2 = /(chr\(\d+\)\.?){10,}/
    condition:
        ($plugin1 or ($plugin2 and $plugin3)) and
        (
            2 of ($malicious*) or
            (1 of ($malicious*) and 1 of ($suspicious*)) or
            1 of ($obfuscated*)
        )
}

rule WordPress_Theme_Infection {
    meta:
        description = "Detect infected theme files"
        severity = "high"
    strings:
        $theme1 = "wp_enqueue_script" nocase
        $theme2 = "wp_enqueue_style" nocase
        $theme3 = "get_template_directory" nocase
        $malicious1 = "eval(" nocase
        $malicious2 = "base64_decode(" nocase
        $malicious3 = "create_function(" nocase
        $malicious4 = "gzinflate(" nocase
        $malicious5 = "str_rot13(" nocase
        $injection1 = "<?php" nocase
        $injection2 = "<?=" nocase
        $injection3 = "<script" nocase
        $injection4 = "javascript:" nocase
    condition:
        (1 of ($theme*)) and
        (
            1 of ($malicious*) or
            (2 of ($injection*) and 1 of ($malicious*))
        )
}

rule WordPress_SEO_Spam {
    meta:
        description = "Detect SEO spam injections"
        severity = "medium"
    strings:
        $spam1 = "<a href=" nocase
        $spam2 = "display:none" nocase
        $spam3 = "position:absolute" nocase
        $spam4 = "visibility:hidden" nocase
        $spam5 = /viagra|cialis|poker|casino|pharmacy|pills|drugs/i
        $spam6 = "overflow:hidden" nocase
        $spam7 = "text-indent:-" nocase
        $spam8 = "z-index:-" nocase
    condition:
        4 of them
}

rule WordPress_Malicious_Redirect {
    meta:
        description = "Detect malicious redirects"
        severity = "high"
    strings:
        $redirect1 = "header(" nocase
        $redirect2 = "Location:" nocase
        $redirect3 = "wp_redirect" nocase
        $redirect4 = "window.location" nocase
        $malicious1 = "eval(" nocase
        $malicious2 = "base64_decode(" nocase
        $malicious3 = "document.write" nocase
        $obfuscated1 = /\\x[0-9a-fA-F]{2}{10,}/
        $obfuscated2 = /(chr\(\d+\)\.?){10,}/
    condition:
        (1 of ($redirect*)) and
        (
            1 of ($malicious*) or
            1 of ($obfuscated*)
        )
}

rule WordPress_Database_Injection {
    meta:
        description = "Detect database injection attempts"
        severity = "critical"
    strings:
        $db1 = "$wpdb" nocase
        $db2 = "wp_posts" nocase
        $db3 = "wp_postmeta" nocase
        $db4 = "wp_options" nocase
        $sql1 = "UNION" nocase
        $sql2 = "SELECT" nocase
        $sql3 = "INSERT" nocase
        $sql4 = "UPDATE" nocase
        $sql5 = "DELETE" nocase
        $malicious1 = "eval(" nocase
        $malicious2 = "base64_decode(" nocase
    condition:
        (2 of ($db*)) and
        (2 of ($sql*)) and
        (1 of ($malicious*))
}

rule WordPress_Core_Modification {
    meta:
        description = "Detect unauthorized core file modifications"
        severity = "critical"
    strings:
        $core1 = "wp-load.php" nocase
        $core2 = "wp-config.php" nocase
        $core3 = "wp-blog-header.php" nocase
        $core4 = "wp-includes" nocase
        $malicious1 = "eval(" nocase
        $malicious2 = "base64_decode(" nocase
        $malicious3 = "system(" nocase
        $malicious4 = "exec(" nocase
        $malicious5 = "shell_exec(" nocase
    condition:
        (1 of ($core*)) and (1 of ($malicious*))
}

rule WordPress_Cryptominer {
    meta:
        description = "Detect cryptocurrency mining code"
        severity = "high"
    strings:
        $miner1 = "CoinHive" nocase
        $miner2 = "crypto-miner" nocase
        $miner3 = "cryptonight" nocase
        $miner4 = "minero" nocase
        $miner5 = "miner.start" nocase
        $miner6 = "wasmMiner" nocase
        $miner7 = "cryptoloot" nocase
        $miner8 = "webmr.js" nocase
        $miner9 = "wpupdates.github.io" nocase
        $miner10 = "cryptonight.wasm" nocase
    condition:
        2 of them
}

rule WordPress_Malvertising {
    meta:
        description = "Detect malicious advertising code"
        severity = "medium"
    strings:
        $ads1 = "document.write" nocase
        $ads2 = "iframe src=" nocase
        $ads3 = "popup" nocase
        $ads4 = "window.open" nocase
        $obf1 = "eval(" nocase
        $obf2 = "base64_decode(" nocase
        $obf3 = "fromCharCode" nocase
        $obf4 = "String.fromCharCode" nocase
        $obf5 = /\\x[0-9a-fA-F]{2}{10,}/
    condition:
        (2 of ($ads*)) and (1 of ($obf*))
}
