#===>#[Protekcje przeciwko prot scanning]#<===#
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP

#===>#[Blokuj spoofed pakiety]#<===#
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/0 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP

#===>#[Blokuj ICMP]#<===#
iptables -t mangle -A PREROUTING -p icmp -j DROP

#===>#[Blokuj nieprawidłowe pakiety]#<===#
iptables -t mangle -A PREROUTING -m conntrack --ctstate new -j DROP

#===>#[Blokuj TCP pakiety, które nie są SYN'em]#<===#
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

#===>#[Blokuj SYN pakiety, z podejrzanym MSS value]#<===#
iptables -t mangle -A PREROUTING -p tcp -m conntrack --cttstate NEW -m tcpmss ! --mss 536:65535 -j DROP

#===>#[Limit RST pakietów]#<===#
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP

#===>#[SSH brute-force protection]#<===#
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --sent
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

#===>#[Limit połączeń TCP na sekunde na IP]#<===#
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP 

#===>#[Limit połączeń na IP]#<===#
iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset

#===>#[Blokuj fragmenty na chainach]#<===#
iptables -t mangle -A PREROUTING -f -j DROP

#===>#[Blokuj pakiety z bogus TCP]#<===#
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP

#===>#[Minecraft Proxy]#<===#
iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-option 8 --tcp-flags FIN,SYN,RST,ACK SYN -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -p tcp -m tcp --dport 25565 -m state --state RELATED.ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 150 --connlimit-mask 32 --connlimit-saddr -j DROP
iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j DROP
iptables -A INPUT -p tcp -m tcp --sport 123 -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -p tcp -m tcp --sport 389 -j REJECT --reject-with icmp-port-unreachable

iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/second --limit-burst 50 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -j DROP
iptables -A INPUT -p tcp -m state --state RELATED.ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -k ACCEPT



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
