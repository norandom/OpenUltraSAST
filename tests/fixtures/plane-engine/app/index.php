<?php
$id = $_GET["id"];
$r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
echo $_GET["name"];
system("ping " . $_GET["host"]);
