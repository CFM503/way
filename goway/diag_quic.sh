#!/bin/bash
cd /mnt/d/SOFT/AI/github/way/goway || exit 1
sudo tc qdisc replace dev lo root netem delay 20ms limit 100000
rm -f /tmp/quicudp.txt
sudo timeout 50 tcpdump -i lo -nn -tttt udp 2>/dev/null > /tmp/quicudp.txt &
TP=$!
sleep 1
./bench_linux -arms "$PWD/cand_dbg_linux" -samples 1 -concurrency 5 \
  -out bench_p3_diag.csv -upstream-template "quic://127.0.0.1:%d" -hs-timeout 10s -v -extra "-log,DEBUG"
sleep 1
sudo pkill -f "tcpdump -i lo" >/dev/null 2>&1
wait $TP 2>/dev/null
sudo tc qdisc del dev lo root netem 2>/dev/null

SRVPORT=$(grep -o 'quic://127.0.0.1:[0-9]*' bench_cand_dbg_linux_s1_c5_client.log | head -1 | cut -d: -f3)
echo "SERVER_PORT: $SRVPORT"
echo "TOTAL_LINES: $(wc -l < /tmp/quicudp.txt)"

# per-second histogram of ALL udp on lo
echo "== all udp per second =="
awk '{print substr($2,1,8)}' /tmp/quicudp.txt | uniq -c

# per-second histogram of SERVER -> CLIENT direction only (src = $4 ends with .PORT)
echo "== server->client per second =="
awk -v p="\\.$SRVPORT\$" '$4 ~ p {print substr($2,1,8)}' /tmp/quicudp.txt | uniq -c

echo "== client->server per second =="
awk -v p="\\.$SRVPORT\$" '$6 ~ p {print substr($2,1,8)}' /tmp/quicudp.txt | uniq -c

cp /tmp/quicudp.txt /mnt/d/SOFT/AI/github/way/goway/quicudp_diag.txt
