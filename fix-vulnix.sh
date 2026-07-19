#!/bin/bash
#  Vulnix Hardening Script — Part B
#  Target : Ubuntu 12.04.1 LTS (HackLAB: Vulnix, 10.10.10.132)
#  Run as : root
#  Usage  : bash fix-vulnix.sh
#
#  Purpose: Closes the misconfiguration classes that allowed full root
#           compromise of the Vulnix VM. Prioritises fixes that neutralise
#           whole categories of attack (not just the specific steps taken),
#           following the Principle of Least Privilege.



# FIX 1: Disable rlogin / rsh / rexec (r-services) 
echo "[1/7] Disabling r-services in /etc/inetd.conf ..."
sed -i '/^login[[:blank:]]/s/^/#/' /etc/inetd.conf   2>/dev/null
sed -i '/^shell[[:blank:]]/s/^/#/' /etc/inetd.conf   2>/dev/null
sed -i '/^exec[[:blank:]]/s/^/#/'  /etc/inetd.conf   2>/dev/null
service inetutils-inetd restart 2>/dev/null || service openbsd-inetd restart 2>/dev/null
echo "      r-services (512/513/514) disabled."

#  FIX 2: Harden /etc/exports 
echo "[2/7] Hardening NFS exports ..."
# Remove any /root export outright — /root must never be exported.
sed -i '\|^/root|d' /etc/exports
# Restrict the vulnix home export to localhost, read-only, root_squash retained.
sed -i 's|^/home/vulnix.*|/home/vulnix 127.0.0.1(ro,root_squash,no_subtree_check)|' /etc/exports
echo "      /root export removed; /home/vulnix restricted to localhost (ro)."

# FIX 3: Reload the NFS export table
echo "[3/7] Reloading NFS export table ..."
exportfs -ra 2>/dev/null
echo "      exportfs reloaded."

# FIX 4: Remove the over-privileged vulnix sudo rule 
echo "[4/7] Removing vulnix sudo rule ..."
sed -i '/vulnix/d' /etc/sudoers
echo "      vulnix sudo entry removed."

#  FIX 5: Remove .rhosts files and planted SSH keys 
echo "[5/7] Removing .rhosts files and clearing planted SSH keys ..."
find /home /root -name ".rhosts" -delete 2>/dev/null
: > /etc/hosts.equiv 2>/dev/null
: > /home/vulnix/.ssh/authorized_keys 2>/dev/null
: > /root/.ssh/authorized_keys 2>/dev/null
echo "      Trust files and planted keys cleared."

# FIX 6: Harden SSH configuration
echo "[6/7] Hardening SSH configuration ..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
grep -q '^IgnoreRhosts'             /etc/ssh/sshd_config && \
  sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config || \
  echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config
grep -q '^RhostsRSAAuthentication'  /etc/ssh/sshd_config && \
  sed -i 's/^#*RhostsRSAAuthentication.*/RhostsRSAAuthentication no/' /etc/ssh/sshd_config || \
  echo 'RhostsRSAAuthentication no' >> /etc/ssh/sshd_config
service ssh restart 2>/dev/null || service sshd restart 2>/dev/null
echo "      PermitRootLogin no; rhosts-style SSH trust disabled."

# FIX 7: Firewall — drop NFS / r-service ports at the network layer
echo "[7/7] Applying iptables firewall rules ..."
iptables -F INPUT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22  -j ACCEPT      # keep SSH reachable
iptables -A INPUT -p tcp --dport 111  -j DROP       # RPC portmapper
iptables -A INPUT -p udp --dport 111  -j DROP
iptables -A INPUT -p tcp --dport 2049 -j DROP       # NFS
iptables -A INPUT -p udp --dport 2049 -j DROP
iptables -A INPUT -p tcp --dport 512  -j DROP       # rexec
iptables -A INPUT -p tcp --dport 513  -j DROP       # rlogin
iptables -A INPUT -p tcp --dport 514  -j DROP       # rsh
iptables-save > /etc/iptables.rules 2>/dev/null
echo "      Firewall active; NFS/r-service ports blocked, SSH open."

