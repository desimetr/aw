<?php
// Collect raw POST data
$data = file_get_contents('php://input');

// Save data to a file
file_put_contents('logs/data.txt', $data . PHP_EOL, FILE_APPEND);

// Respond to the client
echo "Data logged!";
?>
