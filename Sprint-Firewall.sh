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
