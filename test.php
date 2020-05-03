<?php

$code = password_hash('123456', PASSWORD_ARGON2I);
echo $code . "\r\n";

if (password_verify('123456', $code)) {
echo "Success\r\n";
} else {
echo "Failure\r\n";
}
