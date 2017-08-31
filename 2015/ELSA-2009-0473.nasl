# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-0473.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122489");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:46:29 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-0473");
script_tag(name: "insight", value: "ELSA-2009-0473 -  kernel security and bug fix update - [2.6.18-128.1.10.0.1.el5]- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [MM] balloon code needs to adjust totalhigh_pages (Chuck Anderson) [orabug 8300888][2.6.18-128.1.10.el5]- [fs] fix softlockup in posix_locks_deadlock (Josef Bacik ) [496842 476659][2.6.18-128.1.9.el5]- [net] ipv4: remove uneeded bh_lock/unlock from udp_rcv (Neil Horman ) [496044 484590][2.6.18-128.1.8.el5]- [misc] exit_notify: kill the wrong capable check [494270 494271] {CVE-2009-1337}- [misc] fork: CLONE_PARENT && parent_exec_id interaction (Don Howard ) [479963 479964] {CVE-2009-0028}- [scsi] qla2xxx: reduce DID_BUS_BUSY failover errors (Marcus Barrow ) [495635 244967]- [nfs] v4: client crash on file lookup with long names (Sachin S. Prabhu ) [494078 493942] {CVE-2009-1336}- [net] ixgbe: stop double counting frames and bytes (Andy Gospodarek ) [489459 487213]- [xen] x86: update the earlier APERF/MPERF patch (Chris Lalancette ) [495929 493557]- [xen] x86: fix dom0 panic when using dom0_max_vcpus (Chris Lalancette ) [495931 485119]- [net] fix oops when using openswan (Neil Horman ) [496044 484590][2.6.18-128.1.7.el5]- [nfs] remove bogus lock-if-signalled case (Bryn M. Reeves ) [456287 456288] {CVE-2008-4307}- [x86] NONSTOP_TSC in tsc clocksource (Luming Yu ) [493356 474091]- [ppc] keyboard not recognized on bare metal (Justin Payne ) [494293 455232]- [fs] ecryptfs: fix memory leak into crypto headers (Eric Sandeen ) [491255 491256] {CVE-2009-0787}- [xen] x86: silence WRMSR warnings (Chris Lalancette ) [488928 470035]- [ptrace] audit_syscall_entry to use right syscall number (Jiri Pirko ) [488001 488002] {CVE-2009-0834}- [dlm] fix length calculation in compat code (David Teigland ) [491677 487672]- [nfs] fix hung clients from deadlock in flush_workqueue (David Jeffery ) [488929 483627]- [ia64] use current_kernel_time/xtime in hrtimer_start() (Prarit Bhargava ) [490434 485323]- [net] bonding: fix arp_validate=3 slaves behaviour (Jiri Pirko ) [488064 484304]- [net] enic: return notify intr credits (Andy Gospodarek ) [472474 484824]- [input] wacom: 12x12 problem while using lens cursor (Aristeu Rozanski ) [489460 484959]- [net] ehea: improve behaviour in low mem conditions (AMEET M. PARANJAPE ) [487035 483148]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-0473");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-0473.html");
script_cve_id("CVE-2008-4307","CVE-2009-0787","CVE-2009-0834","CVE-2009-1336","CVE-2009-1337");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5PAE~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5debug~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.10.0.1.el5xen~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.10.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.10.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.10.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.10.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

