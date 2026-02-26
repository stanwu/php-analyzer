<?php
define('STRIPE_SECRET_KEY', 'sk_test_FAKE_KEY_PLACEHOLDER');
$db = new MysqliDb('localhost', 'root', 'FAKE_PASSWORD_FOR_TEST', 'mydb');
$api_key = 'FAKE_KEY_1234567890abcdef';
$encoded = 'ZmFrZV9iYXNlNjRfZW5jb2RlZF9rZXlfanVzdF9mb3JfdGVzdGluZ19wdXJwb3Nlcw=='; // fake_base64_encoded_key_just_for_testing_purposes
