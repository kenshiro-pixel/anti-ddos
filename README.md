# Kenshi Shield

GUI/CLI-инсталлятор для hardening Remnawave/Remnanode VPS с Nginx или Caddy.

Проект использует идеи `node-accelerator` и UX-подходы `Reshala-Remnawave-Bedolaga`, но не запускает сторонние remote-install скрипты и не переписывает чужие firewall tables.

## Что есть в MVP

- локальное меню через `whiptail`, `dialog` или безопасный plain fallback;
- read-only аудит ОС, ядра, виртуализации, listeners, firewall и сервисов;
- план с явными портами SSH, Xray и Remnanode API;
- собственная таблица `inet kenshi_shield` без `flush ruleset`;
- явная input policy: совместимый `accept` или подтверждаемый режим `drop` для закрытия лишних портов;
- IPv4/IPv6 allowlist панели и администратора;
- базовые SYN limits и обратимый outbound block TCP/25;
- заготовка country policy для `RU,UA,GE,BY,AM,KZ`;
- профиль shaping без опасного глобального ограничения трафика;
- BBR/sysctl и отдельный advanced SYNPROXY режим;
- отдельные GUI-пункты `Защита`, `Оптимизация`, `Диагностика`;
- tier-aware оптимизация по RAM/CPU: BBR/fq, conntrack, backlog, file limits и journald;
- backup собственного ruleset и rollback.
- отдельный `rollback.sh` для отката только ресурсов Kenshi Shield;
- safety timer после применения firewall;
- flag-drop, anti-scan и per-IP ICMP/SYN/UDP limits.

## Важно

GeoBlock не включается только по названию страны: для enforcement нужен проверенный GeoIP/ASN источник и атомарное обновление наборов. Per-user shaping требует адаптера к реальной идентичности Xray/Remnawave; в MVP глобальный лимит не применяется. XanMod kernel installation оставлена отдельным операторским шагом с reboot и rollback.

Локальный firewall не заменяет provider DDoS scrubbing и не спасает от насыщения uplink. Панель, API, Xray transport и VPN handshake нужно проверять отдельно.

## Запуск

```bash
sudo bash kenshi-shield.sh menu
sudo bash kenshi-shield.sh audit
sudo bash kenshi-shield.sh plan
sudo bash kenshi-shield.sh apply
sudo bash kenshi-shield.sh rollback
# либо
sudo bash rollback.sh
```

Перед `apply` проверьте сгенерированный `/etc/kenshi-shield/firewall.nft`. SSH-порт и адреса панели должны быть указаны явно. Не применяйте правила на production без консольного доступа или проверенного watchdog/recovery пути.

После применения с включённым safety timer сначала проверьте новую SSH-сессию, node API, reverse proxy и нужный VPN transport. Только после этих проверок подтвердите транзакцию:

```bash
sudo bash kenshi-shield.sh commit
```

Если GUI или SSH оборвутся, независимый systemd watchdog по таймауту восстановит предыдущую таблицу `inet kenshi_shield`. Ручной откат выполняется через `sudo bash rollback.sh`; он удаляет только ресурсы Kenshi Shield и восстанавливает сохранённые файлы, включая состояние «файла не было».

Для проверки без применения используйте `KENSHI_DRY_RUN=1`. В режиме `drop` нужно заранее перечислить SSH, публичные Xray-порты, UDP-порты и управляющие CIDR; текущая SSH-сессия сама по себе не считается достаточной проверкой.

## Модули GUI

| Модуль | Что делает |
|---|---|
| `Защита от DDoS` | nftables в собственной таблице, per-IP SYN controls, allowlist, TCP/25 policy и подготовка к CrowdSec/SYNPROXY |
| `Оптимизация` | tier-aware sysctl, BBR/fq, conntrack, socket backlog, systemd limits и journald limits |
| `Диагностика` | read-only отчёт по kernel/BBR/sysctl/conntrack/firewall/CrowdSec/Fail2Ban/listeners |

465/587 остаются разрешёнными: базовая SMTP-политика затрагивает только outbound TCP/25. XanMod kernel, SYNPROXY, GeoIP enforcement, CrowdSec/Fail2Ban installation и per-user eBPF shaping остаются отдельными advanced-профилями: GUI показывает их явно и не применяет без отдельного подтверждения.

## Следующие модули

1. Нативный SSH executor с host-key pinning и операционным watchdog.
2. GeoIP download через versioned signed datasets и nft interval sets.
3. Реальный eBPF/EDT shaper для verified user identity.
4. Проверенный XanMod installer по distro/arch/virtualization.
5. Fail2Ban/CrowdSec adapters и conflict detection.
6. Nginx/Caddy rate-limit templates и integration tests в Debian/Ubuntu VMs.
