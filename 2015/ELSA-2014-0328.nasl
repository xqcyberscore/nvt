# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0328.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123440");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:03:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0328");
script_tag(name: "insight", value: "ELSA-2014-0328 -  kernel security and bug fix update - [2.6.32-431.11.2]- [net] sctp: fix sctp_sf_do_5_1D_ce to verify if peer is AUTH capable (Daniel Borkmann) [1070715 1067451] {CVE-2014-0101}- [vhost] validate vhost_get_vq_desc return value (Michael S. Tsirkin) [1062579 1058677] {CVE-2014-0055}[2.6.32-431.11.1]- [net] netpoll: take rcu_read_lock_bh() in netpoll_send_skb_on_dev() (Florian Westphal) [1063271 1049052]- [fs] cifs: sanity check length of data to send before sending (Sachin Prabhu) [1065668 1062590] {CVE-2014-0069}- [fs] cifs: ensure that uncached writes handle unmapped areas correctly (Sachin Prabhu) [1065668 1062590] {CVE-2014-0069}- [infiniband] ipoib: Report operstate consistently when brought up without a link (Michal Schmidt) [1064464 995300]- [security] selinux: fix broken peer recv check (Paul Moore) [1059991 1043051]- [fs] GFS2: Fix slab memory leak in gfs2_bufdata (Robert S Peterson) [1064913 1024024]- [fs] GFS2: Fix use-after-free race when calling gfs2_remove_from_ail (Robert S Peterson) [1064913 1024024]- [fs] nfs: always make sure page is up-to-date before extending a write to cover the entire page (Scott Mayhew) [1066942 1054493]- [fs] xfs: ensure we capture IO errors correctly (Lachlan McIlroy) [1058418 1021325]- [mm] get rid of unnecessary pageblock scanning in setup_zone_migrate_reserve (Motohiro Kosaki) [1062113 1043353]- [security] selinux: process labeled IPsec TCP SYN-ACK packets properly in selinux_ip_postroute() (Paul Moore) [1055364 1024631]- [security] selinux: look for IPsec labels on both inbound and outbound packets (Paul Moore) [1055364 1024631]- [security] selinux: handle TCP SYN-ACK packets correctly in selinux_ip_postroute() (Paul Moore) [1055364 1024631]- [security] selinux: handle TCP SYN-ACK packets correctly in selinux_ip_output() (Paul Moore) [1055364 1024631]- [edac] e752x_edac: Fix pci_dev usage count (Aristeu Rozanski) [1058420 1029530]- [s390] mm: handle asce-type exceptions as normal page fault (Hendrik Brueckner) [1057164 1034268]- [s390] mm: correct tlb flush on page table upgrade (Hendrik Brueckner) [1057165 1034269]- [net] fix memory information leaks in recv protocol handlers (Florian Westphal) [1039868 1039869]- [usb] cdc-wdm: fix buffer overflow (Alexander Gordeev) [922000 922001] {CVE-2013-1860}- [usb] cdc-wdm: Fix race between autosuspend and reading from the device (Alexander Gordeev) [922000 922001] {CVE-2013-1860}[2.6.32-431.10.1]- [fs] xfs: xfs_remove deadlocks due to inverted AGF vs AGI lock ordering (Brian Foster) [1067775 1059334]- [x86] apic: Map the local apic when parsing the MP table (Prarit Bhargava) [1063507 1061873][2.6.32-431.9.1]- [netdrv] bonding: add NETIF_F_NO_CSUM vlan_features (Ivan Vecera) [1063199 1059777][2.6.32-431.8.1]- [netdrv] enic: remove enic->vlan_group check (Stefan Assmann) [1064115 1057704][2.6.32-431.7.1]- [char] n_tty: Fix unsafe update of available buffer space (Jiri Benc) [1060491 980188]- [char] n_tty: Fix stuck throttled driver (Jiri Benc) [1060491 980188]- [char] tty: Add safe tty throttle/unthrottle functions (Jiri Benc) [1060491 980188]- [char] tty: note race we need to fix (Jiri Benc) [1060491 980188][2.6.32-431.6.1]- [mm] memcg: fix oom schedule_timeout() (Ulrich Obergfell) [1054072 1034237]- [mm] memcg: change memcg_oom_mutex to spinlock (Ulrich Obergfell) [1054072 1034237]- [mm] memcg: fix hierarchical oom locking (Ulrich Obergfell) [1054072 1034237]- [mm] memcg: make oom_lock 0 and 1 based rather than counter (Ulrich Obergfell) [1054072 1034237]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0328");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0328.html");
script_cve_id("CVE-2013-1860","CVE-2014-0055","CVE-2014-0069","CVE-2014-0101");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.11.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

