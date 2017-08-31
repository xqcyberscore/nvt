# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0926.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123351");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:38 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0926");
script_tag(name: "insight", value: "ELSA-2014-0926 -  kernel security and bug fix update - kernel[2.6.18-371.11.1]- [fs] dcache: fix cleanup on warning in d_splice_alias (Denys Vlasenko) [1109720 1080606]- [net] neigh: Make neigh_add_timer symmetrical to neigh_del_timer (Marcelo Ricardo Leitner) [1111195 1109888]- [net] neigh: set NUD_INCOMPLETE when probing router reachability (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ipv6: router reachability probing (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ipv6: probe routes asynchronous in rt6_probe (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ndisc: Update neigh->updated with write lock (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ipv6: remove the unnecessary statement in find_match() (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ipv6: fix route selection if CONFIG_IPV6_ROUTER_PREF unset (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ipv6: Fix def route failover when CONFIG_IPV6_ROUTER_PREF=n (Marcelo Ricardo Leitner) [1106354 1090806]- [net] ipv6: Prefer reachable nexthop only if the caller requests (Marcelo Ricardo Leitner) [1106354 1090806]- [fs] ext4/jbd2: don't wait forever stale tid caused by wraparound (Eric Sandeen) [1097528 980268]- [fs] ext4: Initialize fsync transaction ids in ext4_new_inode() (Eric Sandeen) [1097528 980268]- [fs] jbd2: don't wake kjournald unnecessarily (Eric Sandeen) [1097528 980268]- [fs] jbd2: fix fsync() tid wraparound bug (Eric Sandeen) [1097528 980268]- [infiniband] rds: do not deref NULL dev in rds_iw_laddr_check() (Jacob Tanenbaum) [1093311 1093312] {CVE-2014-2678}- [fs] nfs4: Add recovery for individual stateids - partial backport. (Dave Wysochanski) [1113468 867570]- [fs] nfs4: Don't start state recovery in nfs4_close_done - clean backport. (Dave Wysochanski) [1113468 867570]- [xen] page-alloc: scrub anonymous domain heap pages upon freeing (Vitaly Kuznetsov) [1103648 1103649] {CVE-2014-4021}[2.6.18-371.10.1]- [net] ipv6: fix overlap check for fragments (Francesco Fusco) [1107932 995277]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0926");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0926.html");
script_cve_id("CVE-2014-2678","CVE-2014-4021");
script_tag(name:"cvss_base", value:"4.7");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.11.1.el5~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.11.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.11.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~371.11.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.11.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.11.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.11.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~371.11.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

