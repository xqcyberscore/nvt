# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2315.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.122782");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-25 13:18:49 +0200 (Wed, 25 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2315");
script_tag(name: "insight", value: "ELSA-2015-2315 -  NetworkManager security, bug fix, and enhancement update - ModemManager[1.1.0-8.git20130913]- rfcomm: don't open the ttys until NetworkManager connects them (rh #1251954)[1.1.0-7.git20130913]- iface-modem: fix MODEM_STATE_IS_INTERMEDIATE macro (rh #1200958)NetworkManager[1.0.6-27.0.1]- fix build error on i386[1:1.0.6-27]* build: update vala-tools build requirement (rh #1274000)[1:1.0.6-26]- wifi: emit NEW_BSS on ScanDone to update APs in Wi-Fi device (rh #1267327)[1:1.0.6-25]- vpn: cancel the secrets request on agent timeout (rh #1272023)- vpn: cancel the connect timer when vpn reconnects (rh #1272023)[1:1.0.6-24]- device: fix problem in not managing software devices (rh #1273879)[1:1.0.6-23]- wake-on-lan: ignore by default existing settings (rh #1270194)[1:1.0.6-22]- platform: fix detection of s390 CTC device (rh #1272974)- core: fix queuing activation while waiting for carrier (rh #1079353)[1:1.0.6-21]- core: fix invalid assertion in nm_clear_g_signal_handler() (rh #1183444)[1:1.0.6-20]- rebuild package[1:1.0.6-19]- device: fix race wrongly managing external-down device (2) (rh #1269199)[1:1.0.6-18]- device/vlan: update VLAN MAC address when parent's one changes[1:1.0.6-17]- dhcp6: destroy the lease when destroying a client (rh #1260727)- device: fix race wrongly managing external-down device (rh #1269199)[1:1.0.6-16]- device: silence spurious errors about activation schedule (rh #1269520)[1:1.0.6-15]- core: really fix enslaving team device to bridge (rh #1183444)[1:1.0.6-14]- platform: updating link cache when moving link to other netns (rh #1264361)- nmtui: fix possible crash during secret request (rh #1267672)- vpn: increase the plugin inactivity quit timer (rh #1268030)- core: fix enslaving team device to bridge (rh #1183444)[1:1.0.6-13]- vpn-connection: set the MTU for the VPN IP interface (rh #1267004)- modem-broadband: update modem's supported-ip-families (rh #1263959)- wifi: fix a crash in on_bss_proxy_acquired() (rh #1267462)[1:1.0.6-12]- core: increase IPv6LL DAD timeout to 15 seconds (rh #1101809)[1:1.0.6-11]- platform: better handle devices without permanent address (rh #1264024)[1:1.0.6-10]- dhcp: fix crash in internal DHCP client (rh #1260727)[1:1.0.6-9]- build: fix installing language files (rh #1265117)[1:1.0.6-8]- nmcli: allow creating ADSL connections with 'nmcli connection add' (rh #1264089)[1:1.0.6-7]- ifcfg-rh: ignore GATEWAY from network file for DHCP connections (rh #1262972)[1:1.0.6-6]- device: retry DHCP after timeout/expiration for assumed connections (rh #1246496)- device: retry creation of default connection after link is initialized (rh #1254089)[1:1.0.6-5]- config: add code comments to NetworkManager.conf file- iface-helper: enabled slaac/dhcp4 based on connection setting only (rh #1260243)- utils: avoid generation of duplicated assumed connection for veth devices (rh #1256430)- nmcli: improve handling of wake-on-lan property (rh #1260584)[1:1.0.6-4]- config: fix config-changed signal for s390x and ppc64 archs (rh #1062301)- device: fix handling ignore-auto-dns for IPv6 nameservers (rh #1261428)[1:1.0.6-3]- vpn: fix the tunelled VPN setup (rh #1238840)[1:1.0.6-2]- nmcli: fix argument parsing for config subcommand[1:1.0.6-1]- Align with the upstream 1.0.6 release:- device: add support for configuring Wake-On-Lan (rh #1141417)- device: don't disconnect after DHCP failure when there's static addresses (rh #1168388)- device: provide information about metered connections (rh #1200452)- device: fix an assert fail when cleaning up a slave connection (rh #1243371)- team: add support for setting MTU (rh #1255927)- config: avoid premature exit with configure-and-quit option (rh #1256772)[1:1.0.4-10]- supplicant: fix passing freq_list option to wpa_supplicant (rh #1254461)[1:1.0.4-9]- udev: fix call to ethtool in udev rules (rh #1247156)[1:1.0.4-8]- device: accept multiple addresses in a DHCPv6 lease (rh #1244293)[1:1.0.4-7]- device: fix a crash when unconfiguring a device (rh #1253744)[1:1.0.4-6]- ifcfg-rh: respect DEVTIMEOUT if link is not announced by udev yet (rh #1192633)[1:1.0.4-5]- core: avoid ethtool to autoload kernel module (rh #1247156)[1:1.0.4-4]- device: fix setting of a MTU (rh #1250019)[1:1.0.4-3]- daemon,libnm: fix handling of default routes for assumed connections (rh #1245648)[1:1.0.4-2]- cli: fix verifying flag-based properties (rh #1244048)[1:1.0.4-1]- Align with the upstream 1.0.4 release- Fix the libreswan plugin (rh #1238840)[1:1.0.4-0.2.git20150713.38bf2cb0]- vpn: send firewall zone to firewalld also for VPN connections (rh #1238124)[1:1.0.4-0.1.git20150713.38bf2cb0]- Update to a bit newer 1.0.4 git snapshot, to fix test failures- device: restart ping process when it exits with an error (rh #1128581)[1:1.0.3-2.git20150624.f245b49a]- config: allow rewriting resolv.conf on SIGUSR1 (rh #1062301)[1:1.0.3-1.git20150624.f245b49a]- Update to a bit newer 1.0.4 git snapshot, to fix test failures[1:1.0.3-1.git20150622.9c83d18d]- Update to a 1.0.4 git snapshot:- bond: add support for setting a MTU (rh #1177860)- core: delay initialization of the connection for devices without carrier at startup (rh #1079353)- route-manager: ensure the routes are set up properly with multiple interface in the same subnet (rh #1164441)- config: add support for reloading configuration (rh #1062301)- device: disallow ipv6.method=shared connections early during activation (rh #1183015)- device: don't save the newly added connection for a device until activation succeeds (rh #1174164)- rdisc: prevent solicitation loop for expiring DNS information (rh #1207730)- wifi: Indicate support of wireless radio bands (rh #1200451)- nmcli: Fix client hang upon multiple deletion attempts of the same connection (rh #1168657)- nmcli: Fix documentation for specifying a certificate path (rh #1182575)- device: add support for auto-connecting slave connection when activating a master (rh #1158529)- nmtui: Fix a crash when attempting an activation with no connection present (rh #1197203)- nmcli: Add auto-completion and hints for valid values in enumeration properties (rh #1034126)- core: load the the libnl library from the correct location (rh #1211859)- config: avoid duplicate connection UUIDs (rh #1171751)- device: enable IPv6 privacy extensions by default (rh #1187525)- device: fix handling if DHCP hostname for configure-and-quit (rh #1201497)- manager: reuse the device connection is active on when reactivating it (rh #1182085)- device: reject incorrect MTU settings from an IPv6 RA (rh #1194007)- default-route: allow preventing the connection to override externally configured default route (rh #1205405)- manager: reduce logging for interface activation (rh #1212196)- device: don't assume a connection for interfaces that only have an IPv6 link-local address (rh #1138426)- device: reject hop limits that are too low (CVE-2015-2924) (rh #1217090)[1:1.0.0-17.git20150121.b4ea599c]- dhclient: use fqdn.fqdn for server DDNS updates (rh #1212597)NetworkManager-libreswan[1.0.6-3]- Fix the pty hangup patch (rh #1271973)[1.0.6-2]- Fix recovery after failures (rh #1271973)[1.0.6-1]- Update to a newer upstream release (rh #1243057)network-manager-applet[1.0.6-2]- libnm-gtk: fix a possible crash on widgets destroy (rh #1267326) - libnm-gtk: use symbolic icons for password store menu (rh #1267330)[1.0.6-1]- Align with the 1.0.6 upstream release:- editor: add support for setting MTU on team connections (rh #1255927)- editor: offer bond connections in vlan slave picker (rh #1255735)[1.0.4-1]- Align with the upstream release[1.0.3-2.git20150617.a0b0166]- New snapshot:- editor: let users edit connection.interface-name property (rh #1139536)[1.0.3-1.git20160615.28a0e28]- New snapshot:- applet: make new auto connections only available for current user (rh #1176042)- editor: allow forcing always-on-top windows for installer (rh #1097883)- editor: allow changing bond MTU (rh #1177582)- editor: use ifname instead of UUID in slaves' master property (rh #1083186)- editor: allow adding Bluetooth connections (rh #1229471)[1.0.0-3.git20150122.76569a46]- Drop gnome-bluetooth BR because it does not work with newer versions (rh #1174547)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2315");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2315.html");
script_cve_id("CVE-2015-0272","CVE-2015-2924");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"ModemManager", rpm:"ModemManager~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ModemManager-devel", rpm:"ModemManager-devel~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ModemManager-glib", rpm:"ModemManager-glib~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ModemManager-glib-devel", rpm:"ModemManager-glib-devel~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ModemManager-vala", rpm:"ModemManager-vala~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-config-routing-rules", rpm:"NetworkManager-config-routing-rules~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-glib-devel", rpm:"NetworkManager-glib-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libnm-devel", rpm:"NetworkManager-libnm-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan", rpm:"NetworkManager-libreswan~1.0.6~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-gnome", rpm:"NetworkManager-libreswan-gnome~1.0.6~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libnm-gtk", rpm:"libnm-gtk~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libnm-gtk-devel", rpm:"libnm-gtk-devel~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"network-manager-applet", rpm:"network-manager-applet~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nm-connection-editor", rpm:"nm-connection-editor~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

