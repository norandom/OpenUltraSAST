<?php
// Benign twin of benchmarks/fixtures/php-vulnerable/app.php: the same handlers, each one repaired the way its
// upstream fix did it. Every quick-mode finding here is a false alert (benchmarks/manifests/php-benign.toml).

$conn = mysqli_connect('localhost', 'app', 'app', 'app');

function order_by_code($code)
{
    global $wpdb;
    return $wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}orders WHERE code = %s LIMIT 1", $code));
}

function find_user($conn)
{
    $stmt = mysqli_prepare($conn, 'SELECT * FROM users WHERE name = ?');
    mysqli_stmt_bind_param($stmt, 's', $_GET['name']);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_get_result($stmt);
}

function members_sorted($order)
{
    $order = in_array(strtoupper($order), array('ASC', 'DESC'), true) ? strtoupper($order) : 'ASC';
    return ' ORDER BY u.user_login ' . ('DESC' === $order ? 'DESC' : 'ASC') . ' ';
}

function create_form($data)
{
    return 'INSERT INTO forms (id, label) VALUES (' . intval($data['id']) . ', "x")';
}

function captcha_cleanup($db, $userAgent)
{
    $delete = sprintf(
        "DELETE FROM captcha WHERE useragent = '%s'",
        $db->escape($userAgent)
    );
    $db->query($delete);
}

function ping()
{
    system('ping -c 1 ' . escapeshellarg($_GET['host']));
}

function calculate($formula)
{
    return is_numeric($formula) ? (float) $formula : 0.0;
}

function restore_session()
{
    return json_decode($_COOKIE['session'], true);
}

function greet()
{
    echo 'Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES);
}

function page()
{
    $pages = array('home', 'about');
    include in_array($_GET['page'], $pages, true) ? $_GET['page'] . '.php' : 'home.php';
}

function download()
{
    readfile('/var/www/files/' . basename($_GET['file']));
}

function fetch_preview()
{
    $url = filter_var($_GET['url'], FILTER_VALIDATE_URL);
    $ch = curl_init(wp_http_validate_url($url) ? $url : 'about:blank');
    return curl_exec($ch);
}

function go_back()
{
    wp_safe_redirect(wp_validate_redirect(wp_unslash($_GET['next']), home_url()));
}

function find_order($conn)
{
    $id = intval($_POST['id']);
    $sql = 'SELECT * FROM orders WHERE id = ' . $id;
    return mysqli_query($conn, $sql);
}
