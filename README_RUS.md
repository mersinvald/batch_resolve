[![Build Status](https://travis-ci.org/mersinvald/batch_resolve.svg?branch=master)](https://travis-ci.org/mersinvald/batch_resolve)
[![Crates.io](https://img.shields.io/crates/v/batch_resolve_cli.svg)](https://crates.io/crates/batch_resolve_cli)
[![Gitter](https://img.shields.io/badge/GITTER-join%20chat-green.svg)](https://gitter.im/batch_resolve/Lobby?utm_source=share-link&utm_medium=link&utm_campaign=share-link)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/mersinvald)

# Batch Resolve

Быстрый асинхронный DNS резолвер

## Установка
### Пакеты
Существуют универсальные deb и rpm пакеты, собранные под архитектуру x86_64, их можно найти в [списке релизов и файлов для загрузки.](https://github.com/mersinvald/batch_resolve/tags)

Пользователи Arch Linux могут установить *batch_resolve* [из AUR](https://aur.archlinux.org/packages/batch_resolve/)

Пакеты устанавливают конфиг в /etc/batch_resolve.toml
### Статический бинарник
Для каждого релиза выпускается статический исполняемый файл: 
[Список релизов и файлов для загрузки](https://github.com/mersinvald/batch_resolve/tags)

### Установка с crates.io
Вы можете установить batch_resolve используя пакетный менеджер *cargo*, поставляемый в составе тулкита Rust
```
cargo install batch_resolve_cli
```

## Использование

Входные и выходные данные представлены в виде списка, разделенного переводом строк.
Например, список доменных имен `domains.txt` будет выглядеть так:
```
google.com
rust-lang.org
mozilla.org
```

Получить все `A` записи:
```
batch_resolve --in domains.txt --out hosts.txt --query A
```

Получить `A` и `AAAA` записи:
```
batch_resolve -i domains.txt -o hosts.txt -q A
              -i domains.txt -o hosts.txt -q AAAA  
```

### Конфигурация
По умолчанию `batch_resolve` использует Google Publiс DNS `8.8.8.8` и `8.8.4.4`, `10` раз пытается повторить запрос, вылетевший с Connection Timeout.
Эти параметры и количество запросов в секунду можно изменить в файле конфигурации.

Конфиг может быть расположен по следующим путям (по уменьшению приоритета):
```
batch_resolve.toml
$HOME/.config/batch_resolve.toml
/etc/batch_resolve.toml
```

Конфигурация включает DNS сервера, количество запросов в секунду и количество повторов по таймауту.
```toml
# Адреса DNS серверов
# Если порт не указан -- по умолчанию будет использован полт 53
dns = [
    "8.8.8.8",
    "8.8.4.4"
]

# Количество запросов в секунду
# ВНИМАНИЕ: Google Public DNS гарантированно может обработать максимум 500 запросов в секунду
# Прежде чем использовать настройки с более высоким QPS убедитесь что результаты 
# не отличаются значительно от результатов с настройкой по-умолчанию.
queries_per_second = 500

# Количество повторов запроса по таймауту
retry = 5
```

Шаблон конфигурации можно найти [здесь](batch_resolve.toml)

## Разработка

Для сборки проекта из исходников, склонируйте репозиторий
```
git clone git@github.com:mersinvald/batch_resolve.git
```
И запустите `cagro build`
```
cd batch_resolve
cargo build
```
`batch_resolve` собирается со стабильной версией rust

Если у вас есть предложения по улучшению или багрепорт, пожалуйста заведите Issue.

Pull реквесты приветствуются!

## Лицензия

Проект лицензирован лицензией [MIT](LICENSE.md).

## Поддержать проект

Если этот проект помог сэкономить Ваше время, Вы можете поддержать разработчика чашечкой хорошего кофе :)

* [Поддержать на PayPal](https://www.paypal.me/mersinvald)
* [Поддержать на yasobe.ru](http://yasobe.ru/na/batch_resolve_coffee)