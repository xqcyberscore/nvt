# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1366.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123798");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:42 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1366");
script_tag(name: "insight", value: "ELSA-2012-1366 -  kernel security and bug fix update - [2.6.32-279.11.1.el6]- [net] core: Fix napi_gro_frags vs netpoll path (Amerigo Wang) [857854 845347]- [netdrv] benet: disable BH in callers of be_process_mcc() (Amerigo Wang) [857854 845347]- [net] bonding: remove IFF_IN_NETPOLL flag (Amerigo Wang) [857854 845347]- [mm] fix contig_page_data kABI breakage and related memory corruption (Satoru Moriya) [857012 853007]- [net] sctp: backport sctp cache ipv6 source after route lookup (Michele Baldessari) [858284 855759]- [net] sctp: backport support of sctp multi-homing ipv6 source address selection (Michele Baldessari) [858284 855759]- [net] ipv6: backport RTA_PREFSRC ipv6 source route selection support (Michele Baldessari) [858285 851118]- [netdrv] sfc: Fix maximum number of TSO segments and minimum TX queue size (Nikolay Aleksandrov) [845556 845557] {CVE-2012-3412}- [s390] zfcp: No automatic port_rescan on events (Hendrik Brueckner) [856316 855131]- [fs] xfs: push the AIL from memory reclaim and periodic sync (Dave Chinner) [856686 855139][2.6.32-279.10.1.el6]- [mm] hugetlbfs: close race during teardown of hugetlbfs shared page tables (Rafael Aquini) [857334 856325]- [mm] hugetlbfs: Correctly detect if page tables have just been shared (Rafael Aquini) [857334 856325]- [kernel] sched: fix divide by zero at {thread_group,task}_times (Stanislaw Gruszka) [856703 843771]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1366");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1366.html");
script_cve_id("CVE-2012-3412");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

