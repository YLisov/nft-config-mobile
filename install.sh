#!/usr/bin/env bash
# mobile443-nft — мобильный ASN allowlist + gov/antiscanner blocklist → nftables
#
# Использование:
#   sudo bash <(curl -fsSL https://raw.githubusercontent.com/YLisov/nft-config-mobile/main/install.sh)
#
# Переменные окружения:
#   PORTS="443 8443"  — порты через пробел (по умолчанию: 443)
#
# ⚠️  После установки вручную добавь в /etc/nftables.conf:
#   1. include "/etc/nftables.d/mobile443.nft"   — после flush ruleset
#   2. tcp dport { 443 } jump mobile_filter       — вместо accept

set -euo pipefail

PORTS="${PORTS:-443}"
LIST_DIR="/opt/mobile443/lists"
CACHE_FILE="/var/lib/mobile443/prefixes.txt"
NFT_INCLUDE="/etc/nftables.d/mobile443.nft"
NFT_MAIN="/etc/nftables.conf"
APPLY_SCRIPT="/usr/local/sbin/mobile443-apply-nft.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════╗"
echo "║   mobile443-nft — ASN filter for nftables    ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

[[ "$(id -u)" -ne 0 ]] && { echo -e "${RED}✖ Нужен root${NC}"; exit 1; }

# --- Зависимости ---
for cmd in curl jq nft; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Устанавливаем $cmd..."
    apt-get install -y "$cmd" &>/dev/null
  fi
done

mkdir -p "$LIST_DIR" /var/lib/mobile443 /etc/nftables.d

# --- Blocklists ---
echo -e "${CYAN}==> Скачиваем government список...${NC}"
curl -fsSL "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list" \
  | grep -v '^[[:space:]]*[#$]' | grep -v '^[[:space:]]*$' | sort -u \
  > "$LIST_DIR/government_networks.list"
echo -e "${GREEN}    ✓ $(wc -l < "$LIST_DIR/government_networks.list") записей${NC}"

echo -e "${CYAN}==> Скачиваем antiscanner список...${NC}"
curl -fsSL "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list" \
  | grep -v '^[[:space:]]*[#$]' | grep -v '^[[:space:]]*$' | sort -u \
  > "$LIST_DIR/antiscanner.list"
echo -e "${GREEN}    ✓ $(wc -l < "$LIST_DIR/antiscanner.list") записей${NC}"

# --- Mobile ASN ---
echo -e "${CYAN}==> Скачиваем мобильные ASN из RIPEstat (2-5 мин)...${NC}"

ASNS=(
  # MTS
  8359 13174 21365 30922 34351
  # Beeline / VimpelCom
  3216 16043 16345 42842
  # MegaFon
  31133 8263 6854 50928 48615 47395 47218 43841 42891 41976
  35298 34552 31268 31224 31213 31208 31205 31195 31163 29648
  25290 25159 24866 20663 20632 12396 202804
  # T2 regional
  12958 15378 42437 48092 48190 41330 39374 13116
  # Miranda, Sberbank-Telecom, Rostelecom
  201776 206673 12389
  # Sevastar, T-mobile/Alfa-mobile, Volna-Mobile, MCS/Luhansk, MOTIV
  35816 205638 214257 202498 203451 203561 47204 31499
)

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

for asn in "${ASNS[@]}"; do
  printf "  AS%s " "$asn"
  curl -fsS --max-time 30 \
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}" \
    | jq -r '.data.prefixes[]?.prefix // empty' >> "$TMPFILE" 2>/dev/null || true
  printf "✓\n"
done

sort -u "$TMPFILE" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' > "$CACHE_FILE"
echo -e "${GREEN}    ✓ $(wc -l < "$CACHE_FILE") мобильных префиксов${NC}"

# --- Генерация include-файла ---
generate_include() {
  local gov anti mob
  gov=$(tr '\n' ',' < "$LIST_DIR/government_networks.list" | sed 's/,$//')
  anti=$(tr '\n' ',' < "$LIST_DIR/antiscanner.list" | sed 's/,$//')
  mob=$(tr '\n' ',' < "$CACHE_FILE" | sed 's/,$//')

  cat > "$NFT_INCLUDE" <<NFT
# Сгенерировано mobile443-nft. Не редактировать вручную.
table inet filter {
    set gov_block {
        type ipv4_addr; flags interval; auto-merge;
        elements = { ${gov} }
    }
    set antiscanner_block {
        type ipv4_addr; flags interval; auto-merge;
        elements = { ${anti} }
    }
    set mobile_allow {
        type ipv4_addr; flags interval; auto-merge;
        elements = { ${mob} }
    }
    chain mobile_filter {
        ip saddr @gov_block drop
        ip saddr @antiscanner_block drop
        ip saddr @mobile_allow accept
        drop
    }
}
NFT
}

echo -e "${CYAN}==> Генерируем ${NFT_INCLUDE}...${NC}"
generate_include
echo -e "${GREEN}    ✓ Готово${NC}"

# --- Apply-скрипт для восстановления после перезагрузки ---
cat > "$APPLY_SCRIPT" << 'APPLYEOF'
#!/usr/bin/env bash
set -euo pipefail

LIST_DIR="/opt/mobile443/lists"
CACHE_FILE="/var/lib/mobile443/prefixes.txt"
NFT_INCLUDE="/etc/nftables.d/mobile443.nft"

[[ -f "$LIST_DIR/government_networks.list" ]] || { echo "ERROR: gov list missing";         exit 1; }
[[ -f "$LIST_DIR/antiscanner.list" ]]         || { echo "ERROR: antiscanner list missing"; exit 1; }
[[ -f "$CACHE_FILE" ]]                         || { echo "ERROR: mobile prefix cache missing"; exit 1; }

gov=$(tr '\n' ',' < "$LIST_DIR/government_networks.list" | sed 's/,$//')
anti=$(tr '\n' ',' < "$LIST_DIR/antiscanner.list" | sed 's/,$//')
mob=$(tr '\n' ',' < "$CACHE_FILE" | sed 's/,$//')

cat > "$NFT_INCLUDE" <<NFT
# Сгенерировано mobile443-nft. Не редактировать вручную.
table inet filter {
    set gov_block {
        type ipv4_addr; flags interval; auto-merge;
        elements = { ${gov} }
    }
    set antiscanner_block {
        type ipv4_addr; flags interval; auto-merge;
        elements = { ${anti} }
    }
    set mobile_allow {
        type ipv4_addr; flags interval; auto-merge;
        elements = { ${mob} }
    }
    chain mobile_filter {
        ip saddr @gov_block drop
        ip saddr @antiscanner_block drop
        ip saddr @mobile_allow accept
        drop
    }
}
NFT

nft -f /etc/nftables.conf
echo "[$(date '+%F %T')] mobile443-nft: rules applied from cache"
APPLYEOF

chmod +x "$APPLY_SCRIPT"

# --- Systemd service ---
cat > /etc/systemd/system/mobile443-nft.service << 'UNITEOF'
[Unit]
Description=Apply mobile443 nftables rules from local cache
DefaultDependencies=no
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mobile443-apply-nft.sh
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
UNITEOF

systemctl daemon-reload
systemctl enable mobile443-nft.service
echo -e "${GREEN}    ✓ mobile443-nft.service включён${NC}"

# --- Итог ---
echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}✅ Установка завершена${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Списки и кэш сохранены:"
echo -e "    ${LIST_DIR}/government_networks.list"
echo -e "    ${LIST_DIR}/antiscanner.list"
echo -e "    ${CACHE_FILE}"
echo ""
echo -e "  ${BOLD}⚠️  Требуется ручное изменение ${NFT_MAIN}:${NC}"
echo ""
echo -e "  1. После 'flush ruleset' добавь:"
echo -e "     ${GREEN}include \"/etc/nftables.d/mobile443.nft\"${NC}"
echo ""
echo -e "  2. Замени:"
echo -e "     ${RED}tcp dport { 443 } counter accept${NC}"
echo -e "     на:"
echo -e "     ${GREEN}tcp dport { 443 } jump mobile_filter${NC}"
echo ""
echo -e "  Применить: ${BOLD}nft -f ${NFT_MAIN}${NC}"
echo ""
echo -e "  Проверка:"
echo -e "    nft list chain inet filter mobile_filter"
echo -e "    nft list set inet filter mobile_allow | head -3"
echo ""
