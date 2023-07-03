## lkdr-api

[![Go Reference](https://pkg.go.dev/badge/github.com/jfk9w-go/lkdr-api.svg)](https://pkg.go.dev/github.com/jfk9w-go/lkdr-api)
[![Go Report](https://goreportcard.com/badge/github.com/jfk9w-go/lkdr-api)](https://goreportcard.com/report/github.com/jfk9w-go/lkdr-api)
[![Go Coverage](https://github.com/jfk9w-go/lkdr-api/wiki/coverage.svg)](https://raw.githack.com/wiki/jfk9w-go/lkdr-api/coverage.html)
[![CodeQL](https://github.com/jfk9w-go/lkdr-api/workflows/CodeQL/badge.svg)](https://github.com/jfk9w-go/lkdr-api/actions?query=workflow%3ACodeQL)

Клиент для сервиса ФНС [Мои Чеки Онлайн](https://lkdr.nalog.ru/login).

### Пример

Выполнение авторизации (если нужно, код будет запрошен из стандартного ввода) и получение некоторой информации
о чеках с выводом в консоль.

Использует [RuCaptcha](https://rucaptcha.com) для получения токена капчи для авторизации.

Переменная `LKDR_TOKENS_FILE` должна содержать путь к файлу с токенами в формате JSON. Если файл
не существует, авторизация будет выполнена автоматически, но для этого необходимо задать корректный
ключ для [RuCaptcha](https://rucaptcha.com) в переменной `RUCAPTCHA_KEY`.

`LKDR_DEVICE_ID` можно вытащить прямо с сайта сервиса.

`LKDR_USER_AGENT` рекомендуется указывать как у реального браузера.

```bash
RUCAPTCHA_KEY="key" LKDR_PHONE="79999999999" LKDR_TOKENS_FILE="/tmp/lkdr-tokens.json" LKDR_DEVICE_ID="deviceId" LKDR_USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" go run example/main.go
```
