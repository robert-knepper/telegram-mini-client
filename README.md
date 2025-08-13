# telegram-mini-client
Communicate with MTProto and send request and receive Response

### Run all Tests
```shell
vendor/bin/phpunit
```

### Code Coverage
install xdebug
```shell
sudo apt install php-xdebug
php -m | grep xdebug
```

Generate code coverage:
```shell
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-text
```