iptables=/sbin/iptables

#===>#[Na jakim porcie Aegis jest uruchomiony]#<===#
read -p "Na jakim porcie Aegis jest uruchomiony: " port

#===>#[Czy połączenia linuxa powinny być blokowane?]#<===#
block_linux_connections=true

limit_global_connections=true
limit_global_connections_max=1

#===>#[Limit połączeń na sekunde. Pomoże to zastopować zmasowane ataki.]#<===#
burstconns=30

$iptables -A INPUT -p tcp --dport $port --syn -m limit --limit $burstconns/s -j ACCEPT
$iptables -A INPUT -p tcp --dport $port --syn -j DROP

if $block_linux_connections ; then
    $iptables -A INPUT -p tcp -m tcp --syn --tcp-option 8 --dport $port -j REJECT
    echo 'Blokowanie połączeń z linuxa.'
fi 

if $limit_global_connections ; then
    $iptables -I INPUT -p tcp --dport $port -m state --state NEW -m limit --limit $limit_global_connections_max/s -j ACCEPT
    $iptables -A INPUT -p tcp -m tcp --dport $port -j ACCEPT
    $iptables -A INPUT -p tcp -m tcp --dport $port -m state --state RELATED.ESTABLISHED -j ACCEPT
    $iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 150 --connlimit-mask 32 --connlimit-saddr -j DROP
    $iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j DROP
    echo 'Limit globalnych połączeń.'
fi

echo "Sprint-Firewall applied successfully."
