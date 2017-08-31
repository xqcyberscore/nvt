# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-0326.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122501");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:46:47 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-0326");
script_tag(name: "insight", value: "ELSA-2009-0326 -  kernel security and bug fix update - [2.6.18-128.1.6.0.1.el5]- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [MM] balloon code needs to adjust totalhigh_pages (Chuck Anderson) [orabug 8300888][2.6.18-128.1.6.el5]- [x86] add nonstop_tsc flag in /proc/cpuinfo (Luming Yu ) [489310 474091][2.6.18-128.1.5.el5]- Revert: [x86_64] fix gettimeoday TSC overflow issue (Prarit Bhargava ) [489847 467942][2.6.18-128.1.4.el5]- [x86_64] mce: do not clear an unrecoverable error status (Aristeu Rozanski ) [490433 489692]- [wireless] iwlwifi: booting with RF-kill switch enabled (John W. Linville ) [489846 482990]- [x86_64] fix gettimeoday TSC overflow issue (Prarit Bhargava ) [489847 467942]- [misc] signal: modify locking to handle large loads (AMEET M. PARANJAPE ) [489457 487376]- [x86] TSC keeps running in C3+ (Luming Yu ) [489310 474091]- [net] fix icmp_send and icmpv6_send host re-lookup code (Jiri Pirko ) [489253 439670] {CVE-2009-0778}[2.6.18-128.1.3.el5]- [net] skfp_ioctl inverted logic flaw (Eugene Teo ) [486539 486540] {CVE-2009-0675}- [net] memory disclosure in SO_BSDCOMPAT gsopt (Eugene Teo ) [486517 486518] {CVE-2009-0676}- [x86] limit max_cstate to use TSC on some platforms (Tony Camuso ) [488239 470572]- [ptrace] correctly handle ptrace_update return value (Jerome Marchand ) [487394 483814]- [misc] minor signal handling vulnerability (Oleg Nesterov ) [479963 479964] {CVE-2009-0028}- [firmware] dell_rbu: prevent oops (Don Howard ) [482941 482942]- [gfs2] panic in debugfs_remove when unmounting (Abhijith Das ) [485910 483617][2.6.18-128.1.2.el5]- [scsi] libata: sas_ata fixup sas_sata_ops (David Milburn ) [485909 483171]- [fs] ecryptfs: readlink flaw (Eric Sandeen ) [481606 481607] {CVE-2009-0269}- [qla2xxx] correct endianness during flash manipulation (Marcus Barrow ) [485908 481691]- [net] ixgbe: frame reception and ring parameter issues (Andy Gospodarek ) [483210 475625]- [misc] fix memory leak during pipe failure (Benjamin Marzinski ) [481576 478643]- [block] enforce a minimum SG_IO timeout (Eugene Teo ) [475405 475406] {CVE-2008-5700}- [nfs] handle attribute timeout and u32 jiffies wrap (Jeff Layton ) [483201 460133]- [fs] ext[234]: directory corruption DoS (Eugene Teo ) [459601 459604] {CVE-2008-3528}- [net] deadlock in Hierarchical token bucket scheduler (Neil Horman ) [481746 474797]- [wireless] iwl: fix BUG_ON in driver (Neil Horman ) [483206 477671]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-0326");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-0326.html");
script_cve_id("CVE-2008-3528","CVE-2008-5700","CVE-2009-0028","CVE-2009-0269","CVE-2009-0322","CVE-2009-0675","CVE-2009-0676","CVE-2009-0778");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5PAE~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5debug~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~128.1.6.0.1.el5xen~1.4.1~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.6.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.6.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.6.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~128.1.6.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

