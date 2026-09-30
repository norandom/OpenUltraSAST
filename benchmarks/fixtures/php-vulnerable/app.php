<?php
// Intentionally vulnerable PHP fixture for the quick-mode PHP rules. Do not deploy.
// Each handler has one labeled weakness (benchmarks/manifests/php-vulnerable.toml); the fixed twin is
// benchmarks/fixtures/php-benign/app.php.

$conn = mysqli_connect('localhost', 'app', 'app', 'app');

function order_by_code($code)
{
    global $wpdb;
    return $wpdb->get_var("SELECT id FROM {$wpdb->prefix}orders WHERE code = '" . $code . "' LIMIT 1");
}

function find_user($conn)
{
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
}

function members_sorted($order)
{
    $order = esc_sql($order); // escaping does not protect an unquoted ORDER BY
    return " ORDER BY u.user_login {$order} ";
}

function create_form($data)
{
    return 'INSERT INTO forms (id, label) VALUES (' . $data['id'] . ', "x")';
}

function captcha_cleanup($db, $userAgent)
{
    $delete = sprintf(
        "DELETE FROM captcha WHERE useragent = '%s'",
        $userAgent
    );
    $db->query($delete);
}

function ping()
{
    system('ping -c 1 ' . $_GET['host']);
}

function calculate($formula)
{
    eval('$value = ' . $formula . ';');
    return $value;
}

function restore_session()
{
    return unserialize($_COOKIE['session']);
}

function greet()
{
    echo 'Hello ' . $_GET['name'];
}

function page()
{
    include $_GET['page'] . '.php';
}

function download()
{
    readfile('/var/www/files/' . $_GET['file']);
}

function fetch_preview()
{
    $ch = curl_init($_GET['url']);
    return curl_exec($ch);
}

function go_back()
{
    header('Location: ' . $_GET['next']);
}

// Not visible to a line rule: the value reaches the sink through a variable on another line.
function find_order($conn)
{
    $id = $_POST['id'];
    $sql = "SELECT * FROM orders WHERE id = '" . $id . "'";
    return mysqli_query($conn, $sql);
}
