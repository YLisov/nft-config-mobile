# mobile443-nft

Разовая загрузка мобильных ASN + gov/antiscanner blocklist → nftables sets.

## Логика фильтрации

```
tcp dport 443 → mobile_filter:
  ip из gov_block        → DROP   (сети РКН/госорганов)
  ip из antiscanner_block → DROP  (сканеры и проверяльщики)
  ip из mobile_allow     → ACCEPT (мобильные операторы РФ)
  остальное              → DROP
```

## Установка

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/YLisov/nft-config-mobile/main/install.sh)
```

Другие порты:

```bash
sudo PORTS="443 8443" bash <(curl -fsSL https://raw.githubusercontent.com/YLisov/nft-config-mobile/main/install.sh)
```

Занимает 2-5 минут (запросы в RIPEstat по каждому ASN).

## После установки — изменить /etc/nftables.conf

```nft
define admins = { 1.2.3.4 }

flush ruleset

include "/etc/nftables.d/mobile443.nft"   # <-- добавить

table inet filter {
    chain input {
        type filter hook input priority -5; policy drop;

        iifname "lo" notrack accept
        ct state { established, related } counter accept
        ct state invalid counter drop
        iifname { "eth1" } counter accept
        ip saddr $admins counter accept
        tcp dport { 443 } jump mobile_filter  # <-- accept → jump
    }
}
```

Применить:

```bash
nft -f /etc/nftables.conf
```

## Проверка

```bash
nft list chain inet filter mobile_filter
nft list set inet filter mobile_allow | grep "Number of entries"
nft list set inet filter gov_block | grep "Number of entries"
```

## Что устанавливается

| Файл | Назначение |
|------|-----------|
| `/opt/mobile443/lists/government_networks.list` | Кэш: сети РКН |
| `/opt/mobile443/lists/antiscanner.list` | Кэш: сканеры |
| `/var/lib/mobile443/prefixes.txt` | Кэш: мобильные префиксы |
| `/etc/nftables.d/mobile443.nft` | Генерируемый include-файл |
| `/usr/local/sbin/mobile443-apply-nft.sh` | Скрипт применения из кэша |
| `/etc/systemd/system/mobile443-nft.service` | Автозагрузка при старте системы |

После перезагрузки правила восстанавливаются из локального кэша — без повторной загрузки из сети.

## Источники списков

- Blocklist: [shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists)
- Mobile ASN: RIPEstat API (МТС, Билайн, МегаФон, Теле2, Ростелеком и др.)
