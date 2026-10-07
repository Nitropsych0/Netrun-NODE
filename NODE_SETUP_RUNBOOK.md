# NETRUN Node Setup Runbook

Выверенная процедура развёртывания и эксплуатации proxy-ноды.
Собрана из инцидентов 2026-05-12 … 2026-05-21 (см. раздел «История граблей»).

**Источник истины для скриптов:** `https://github.com/Tmwyw/node_runtime_new.git`
(содержит `install_node_v2.sh` + `scripts/node_followup_v2.sh` со всеми фиксами).

---

## 0. Предусловия

- Vultr Cloud Compute, **Ubuntu 24.04 LTS**, ≥2 vCPU / 4 GB RAM / 100 GB NVMe
- root-доступ (SSH-пароль или ключ)
- IPv6 включён на инстансе (Vultr выдаёт /64)
- Нода будет держать ~4000-5000 портов 3proxy + столько же IPv6 на интерфейсе

---

## 1. Установка ноды с нуля

**✅ ПРОВЕРЕНО БОЕМ 2026-05-22** на свежей reinstalled Vultr Ubuntu 24.04 (Tokyo) — ставится одной командой до ALL GREEN. Запускать **с orchestrator** (host key чистится автоматически):

```bash
ssh-keygen -R <NODE_IP> 2>/dev/null
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@<NODE_IP> 'bash -s' <<'REMOTE'
set -e
cd /root && rm -rf node_runtime_new
git clone -q https://github.com/Tmwyw/node_runtime_new.git
cd node_runtime_new
grep -q "nft flush ruleset" install_node_v2.sh || { echo "OLD repo — push fix"; exit 1; }
chmod +x install_node_v2.sh scripts/*.sh
bash install_node_v2.sh --clean --remove-legacy-root
bash scripts/node_followup_v2.sh
# финальный self-check
for k in "/health:$(curl -s -m5 -o/dev/null -w%{http_code} http://127.0.0.1:8085/health)" \
         "agent:$(systemctl is-active netrun-node-agent)" "nftables:$(systemctl is-active nftables)" \
         "TasksMax:$(systemctl show netrun-node-agent -p TasksMax --value)" \
         "symlink:$(readlink /root/proxyserver)" "watchdog:$(systemctl is-active netrun-watchdog.timer)"; do echo "  $k"; done
REMOTE
```

Эталон: `/health:200 agent:active nftables:active TasksMax:infinity symlink:/opt/netrun/proxyserver watchdog:active`.

> **Баг свежих нод (исправлен 2026-05-22):** Ubuntu 24.04 идёт с UFW, чьи правила в nftables используют xtables-compat (`xt match "icmp6"`). После `apt purge ufw` они остаются в live-ruleset; `nft list ruleset > /etc/nftables.conf` записывал их, и `systemctl start nftables` падал → install прерывался. Фикс: `configure_nftables` делает `nft flush ruleset` перед записью конфига. На старых нодах не проявлялось (ufw давно вычищен).

### Что делает `install_node_v2.sh`

| Шаг | Зачем |
|---|---|
| `disable_ufw` (apt purge) | UFW при boot ставит default-deny → блокирует 8085 + proxy-порты. Убираем навсегда. |
| `pin_dns_resolvers` + `chattr +i` | Vultr regional DNS ненадёжен (особенно Mumbai). Пинимся на 1.1.1.1/8.8.8.8, лочим immutable. |
| `configure_sysctl` | `pid_max=4M`, `threads-max=4M`, `somaxconn=8192` в `99-netrun.conf`; `nf_conntrack_max` по RAM (1 запись на 8 КБ, степень двойки, 65536..1048576: 2c/4GB → 262144, ~85 МБ при полной таблице) + `/etc/modules-load.d/netrun-conntrack.conf` и udev-правило `90-netrun-conntrack.rules`, чтобы значение переживало reboot (раньше `systemd-sysctl` отрабатывал до загрузки `nf_conntrack` и ядро оставляло дефолт 65536). Дефолтные 65536 не держат 4000+ 3proxy → fork EAGAIN. **Делает `modprobe nf_conntrack` перед `sysctl -p`** (на чистой ноде модуль не загружен). **Плюс пишет `98-netrun-ipv6.conf`** (DAD off + `mld_max_msf=1`) — снижает MLD-нагрузку от тысяч IPv6; имя 98- чтобы `node_followup_v2.sh` (перезаписывает только 99-) его не затирал. |
| `install_trend_monitor` | `/opt/netrun/scripts/trend_monitor.sh` + cron `*/5` (`/etc/cron.d/netrun-trend-monitor`) — логгер метрик в `/var/log/netrun-trend.log` (см. §5). Раньше ручной шаг. |
| `configure_file_limits` | `nofile=1M`, `nproc=unlimited` + `DefaultTasksMax=infinity` в `/etc/systemd/system.conf.d/`. |
| `install_systemd_service` | node-agent на :8085 **с drop-in override** `/etc/systemd/system/netrun-node-agent.service.d/99-netrun-limits.conf` → `TasksMax=infinity` (НЕ через sed — он ломается на `\n`). |
| `ensure_legacy_root_proxyserver_symlink` | `/root/proxyserver` → симлинк на `/opt/netrun/proxyserver`. Иначе legacy-скрипты пишут в одну директорию, а node-agent в другую → рассинхрон. |
| `install_3proxy_restore_unit` | `netrun-3proxy-restore.service` — bounded parallel (`xargs -P 4` + `setsid`), НЕ fork-bomb. |

### Что делает `node_followup_v2.sh`

- **watchdog v3** (`/opt/netrun/scripts/watchdog_probe.sh`, timer каждые 60с):
  - 5 fails `localhost:8085/health` → `systemctl restart netrun-node-agent` (cooldown 10 мин)
  - 20 fails (~20 мин downtime) → `reboot` (cooldown 4 ч) — лечит зависший сетевой стек/Vultr-block

> DAD off + `mld_max_msf=1` (`/etc/sysctl.d/98-netrun-ipv6.conf`) и `trend_monitor.sh` теперь ставит **`install_node_v2.sh`** (`configure_sysctl` / `install_trend_monitor`) — раньше были ручными твиками, выявленными аудитом нод 2026-05-30. `node_followup_v2.sh` их НЕ трогает.

---

## 2. Пост-установочная проверка (обязательно)

```bash
ssh root@<NODE_IP> 'bash -s' <<'REMOTE'
echo "/health:    $(curl -s -m 5 -o /dev/null -w %{http_code} http://127.0.0.1:8085/health)"
echo "TasksMax:   $(systemctl show netrun-node-agent -p TasksMax --value)"
echo "symlink:    $(readlink /root/proxyserver || echo NOT-A-SYMLINK)"
echo "pid_max:    $(cat /proc/sys/kernel/pid_max)"
echo "conntrack:  $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null) (boot: $(cat /etc/modules-load.d/netrun-conntrack.conf 2>/dev/null | grep -c '^nf_conntrack$'))"
echo "watchdog:   $(systemctl is-active netrun-watchdog.timer)"
echo "restore:    $(systemctl is-enabled netrun-3proxy-restore.service)"
echo "ufw:        $(command -v ufw >/dev/null && echo PRESENT-BAD || echo absent-ok)"
REMOTE
```

Эталон:
```
/health:    200
TasksMax:   infinity
symlink:    /opt/netrun/proxyserver
pid_max:    4194304
conntrack:  262144 (boot: 1)      # 2c/4GB; 131072 на 2 GB, 524288 на 8 GB
watchdog:   active
restore:    enabled
ufw:        absent-ok
```

---

## 3. Регистрация ноды в orchestrator

### 3.1 API-ключ (ВАЖНО — security)

`server.js`: если `NODE_AGENT_API_KEY` пустой → **node-agent принимает запросы БЕЗ авторизации** (открыт на 0.0.0.0:8085 всему интернету). Для prod **обязательно** задать ключ и согласовать с orchestrator:

```bash
# на ноде — задать ключ в env node-agent
KEY=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 40)
echo "$KEY"   # запиши — он же пойдёт в orchestrator nodes.api_key
sed -i "s|^# *NODE_AGENT_API_KEY=.*|NODE_AGENT_API_KEY=$KEY|" /opt/netrun/.env 2>/dev/null \
  || echo "NODE_AGENT_API_KEY=$KEY" >> /opt/netrun/.env
# убедись что service читает /opt/netrun/.env (EnvironmentFile) либо передай через Environment=
systemctl restart netrun-node-agent
```
> Если node-agent не читает .env — добавь `EnvironmentFile=/opt/netrun/.env` в `netrun-node-agent.service` или `Environment=NODE_AGENT_API_KEY=...`. **Ключ на ноде ДОЛЖЕН совпадать с `nodes.api_key` в orchestrator БД**, иначе orchestrator получит 401.

### 3.2 Регистрация в orchestrator (`51.38.205.194`)

```sql
-- 1. Добавить ноду (api_key = тот же что задан на ноде в 3.1)
INSERT INTO nodes (id, name, geo, url, api_key, status, runtime_status)
VALUES ('xx-city-01', 'NETRUN City', 'XX', 'http://<NODE_IP>:8085', '<NODE_API_KEY>', 'ready', 'active');

-- 2. Привязать SKU к ноде (binding)
INSERT INTO sku_node_bindings (sku_id, node_id, weight, max_batch_size, is_active)
VALUES ((SELECT id FROM skus WHERE code='ipv6_xx'), 'xx-city-01', 100, 100, true);
```

После — refill scheduler сам заполнит pool через node-agent `/generate` (~20-30 мин до полного pool).

> **TasksMax в service template** теперь = `infinity` (исправлено 2026-05-21, было 32768). Свежая нода безопасна даже без drop-in override. install_v2 всё равно кладёт drop-in для двойной защиты.

---

## 4. Recovery — нода легла (unreachable)

### Симптом: SSH / :8085 / ping timeout, но в Vultr-панели статус `Running`

**Это не баг ноды — это зависший сетевой стек или Vultr abuse-block.** Лечится hard-reboot:

1. **Vultr-панель → инстанс → Restart Server** (power-cycle через гипервизор; SSH/console-login НЕ нужны)
2. Подожди ~90 сек
3. Проверь: `ssh root@<NODE_IP> 'uptime'`
4. После boot `netrun-3proxy-restore.service` поднимет 3proxy сам. Строки генератора `@reboot … proxy-startup_<p>.sh` агент удаляет из crontab, а лишние копии 3proxy гасит через минуту после старта (инцидент 2026-10-07: каждая партия запускалась дважды — README, «Boot duplicates»)

> ⚠️ **noVNC console «Login incorrect»** — это спецсимволы пароля в noVNC keyboard layout, НЕ проблема ноды. Для recovery console не нужен — только Restart Server. Если нужен console-доступ — поставь root-пароль без спецсимволов.

### Если после reboot DB показывает старый inventory (phantom)

После clean reinstall DB помнит старые `available` порты которых физически нет. Архивировать:

```sql
UPDATE proxy_inventory SET status='archived', archived_at=now(), updated_at=now()
 WHERE node_id=(SELECT id FROM nodes WHERE name='NETRUN City')
   AND status IN ('available','sold','allocated_pergb','pending_validation','reserved','expired_grace','invalid');
UPDATE traffic_accounts SET status='expired', updated_at=now()
 WHERE status='active' AND id IN (
   SELECT DISTINCT t.id FROM traffic_accounts t
   JOIN proxy_inventory i ON i.traffic_account_id=t.id
   JOIN nodes n ON n.id=i.node_id WHERE n.name='NETRUN City');
```
→ refill пересоздаст pool с нуля.

### Нода в `runtime_status='degraded'` → не продаётся / refill раздувает

```sql
UPDATE nodes SET runtime_status='active', heartbeat_failures=0, updated_at=now()
 WHERE runtime_status='degraded';
```
> degraded ставит traffic_poll после N timeout'ов. Авто-recovery в active **пока не реализован** (техдолг) — возвращать вручную.

---

## 5. Мониторинг тренда

`/opt/netrun/scripts/trend_monitor.sh` (cron `*/5`) пишет в `/var/log/netrun-trend.log`. **Ставится автоматически `install_node_v2.sh` (`install_trend_monitor`) — ручной шаг больше не нужен.**

```bash
ssh root@<NODE_IP> 'tail -10 /var/log/netrun-trend.log'
```

Метрики: `threads / 3proxy / listen / estab / ipv6 / mem / conntrack / cronpids / fd / load`.

**Здоровая нода:** все метрики стабильны во времени. **Тревога:** `ipv6=` или `threads=` или `fd=` ползут вверх → нода below-target и refill раздувает IPv6 (см. грабли #6).

---

## 6. Orchestrator env-tune (`/opt/netrun-orchestrator/.env`)

Для нод с крупными pergb-клиентами (1000+ портов):

```ini
TRAFFIC_POLL_REQUEST_TIMEOUT_SEC=30   # default 10 — мало для опроса 2000+ портов; должен быть
                                      # БОЛЬШЕ NODE_AGENT_NFT_DUMP_TIMEOUT_MS/1000 (20 с) + парсинг — нужен на ЛЮБОЙ ноде
TRAFFIC_POLL_DEGRADE_AFTER=15         # default 5 — не валить degraded по мелочи
PROXY_ALLOW_DEGRADED_NODES=true       # degraded ноды продолжают участвовать в reserve/refill
```
После правки: `systemctl restart netrun-orchestrator netrun-orchestrator-traffic-poll netrun-orchestrator-refill netrun-orchestrator-worker`

---

## История граблей (почему каждый шаг важен)

| # | Симптом | Корень | Фикс |
|---|---|---|---|
| 1 | Ноды ребутятся каждые сутки секунда-в-секунду | watchdog v1 делал `/sbin/reboot` после 3 fails localhost-health | watchdog v3 (restart→reboot tiers) |
| 2 | После reboot 3proxy не поднимаются (phantom inventory) | restore-скрипт `for cfg; do 3proxy & done` → fork EAGAIN | bounded parallel `xargs -P 4` + setsid |
| 3 | fork rejected по всей системе, console login fail | `kernel.pid_max=65536` + `TasksMax=32768` default | pid_max=4M + TasksMax=infinity (drop-in, НЕ sed) |
| 4 | `/root` и `/opt/netrun` — две разные cfg-директории, partial bind | старый install без симлинка | `/root/proxyserver` → симлинк |
| 5 | Нода unreachable, VM Running | зависший сетевой стек (вероятно MLD overload от тысяч IPv6) | DAD off + clean install сброс IPv6 + watchdog v3 reboot fallback |
| 6 | Одна нода ipv6/threads растут, degraded, US-покупка 400 | крупный клиент (2000 портов) → traffic_poll timeout → degraded → refill раздувает | env-tune timeout/degrade/allow_degraded |

### Ключевые принципы
1. **Vultr Restart Server** — универсальное лекарство при unreachable. Console-login для этого не нужен.
2. **DB ≠ реальность.** После reboot/reinstall всегда сверять `proxy_inventory` с реально слушающими портами.
3. **Один cfg-файл 3proxy = ~100-500 портов** (range), `pgrep -c 3proxy` мал, но `ss -tln` показывает тысячи — это норма.
4. **3proxy bind на IPv4 listen (`-i<ip>`), egress по IPv6 (`-6 -e<v6>`).** Loopback-тесты бесполезны.
5. **Geo по IP**: ipinfo.io/MaxMind корректны; IP2Location может врать (устаревшая база) — не наш баг.

---

## Открытые техдолги (кандидаты в ops-wave)
1. **degraded→active авто-recovery** в traffic_poll (сейчас вручную SQL).
2. **refill раздувает IPv6** на below-target нодах — legacy `proxy-startup` не чистит старые IPv6/процессы при regenerate.
3. **`nodes.last_heartbeat_at`** колонка не пишется (мёртвая).
4. **reserve 400 → бот пишет «оркестратор недоступен»** — различать бизнес-ошибки от недоступности.
5. **Стратегия:** Vultr периодически abuse-блокает proxy-трафик. Долгосрочно — сменить провайдера (M247/BuyVM/HostUS) или nft-фильтр abusive outbound.

---

*Последнее обновление: 2026-05-21. Все 6 нод на v2, 20h+ uptime без падений.*
