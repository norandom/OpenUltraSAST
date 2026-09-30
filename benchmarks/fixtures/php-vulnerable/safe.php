<?php
// Safe equivalents. None of these lines should produce a finding.

function order_by_code_safe($code)
{
    global $wpdb;
    return $wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}orders WHERE code = %s LIMIT 1", $code));
}

function orders_in_safe($ids)
{
    global $wpdb;
    $ids_format = implode(', ', array_fill(0, count($ids), '%d'));
    return $wpdb->prepare('SELECT * FROM orders WHERE id IN (' . $ids_format . ')', $ids);
}

function page_limit_safe($page)
{
    return ' LIMIT ' . intval($page) . ', 20';
}

function quoted_escaped_safe($name)
{
    return "SELECT * FROM users WHERE name = '" . esc_sql($name) . "'";
}

function ping_safe()
{
    system('ping -c 1 ' . escapeshellarg($_GET['host']));
}

function version_safe()
{
    exec('git describe --tags', $output);
    return $output;
}

function greet_safe()
{
    echo 'Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES);
}

function download_safe()
{
    readfile('/var/www/files/' . basename($_GET['file']));
}

function restore_safe($raw)
{
    return unserialize($raw, ['allowed_classes' => false]);
}

function query_args_safe()
{
    $args = [];
    $args['include'] = [(int) $_REQUEST['p']];
    return $args;
}

function comment_only()
{
    // system('rm -rf ' . $_GET['dir']) would be dangerous but this is a comment
    # eval($_POST['code']) is a comment too
    return 'ok';
}
