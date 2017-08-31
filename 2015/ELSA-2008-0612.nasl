# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0612.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122564");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:48:03 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0612");
script_tag(name: "insight", value: "ELSA-2008-0612 -  kernel security and bug fix update - [2.6.18-92.1.10.0.1.el5]- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]- [splice] Fix bad unlock_page() in error case (Jens Axboe) [orabug 6263574]- [dio] fix error-path crashes (Linus Torvalds) [orabug 6242289]- [NET] fix netpoll race (Tina Yang) [orabugz 5791][2.6.18-92.1.10.el5]- [ia64] softlock: prevent endless warnings in kdump (Neil Horman ) [456117 453200][2.6.18-92.1.9.el5]- [misc] signaling msgrvc() should not pass back error (Jiri Pirko ) [455278 452533]- [ia64] properly unregister legacy interrupts (Prarit Bhargava ) [450337 445886][2.6.18-92.1.8.el5]- [net] randomize udp port allocation (Eugene Teo ) [454571 454572]- [tty] add NULL pointer checks (Aristeu Rozanski ) [453425 453154] {CVE-2008-2812}- [net] sctp: make sure sctp_addr does not overflow (David S. Miller ) [452482 452483] {CVE-2008-2826}- [sys] sys_setrlimit: prevent setting RLIMIT_CPU to 0 (Neil Horman ) [437121 437122] {CVE-2008-1294}- [net] sit: exploitable remote memory leak (Jiri Pirko ) [446038 446039] {CVE-2008-2136}- [misc] ttyS1 lost interrupt, stops transmitting v2 (Brian Maly ) [455256 451157]- [misc] ttyS1 loses interrupt and stops transmitting (Simon McGrath ) [443071 440121][2.6.18-92.1.7.el5]- [x86_64]: extend MCE banks support for Dunnington, Nehalem (Prarit Bhargava ) [451941 446673]- [nfs] address nfs rewrite performance regression in RHEL5 (Eric Sandeen ) [448685 436004]- [mm] Make mmap() with PROT_WRITE on RHEL5 (Larry Woodman ) [450758 448978]- [i386]: Add check for supported_cpus in powernow_k8 driver (Prarit Bhargava ) [450866 443853]- [i386]: Add check for dmi_data in powernow_k8 driver (Prarit Bhargava ) [450866 443853]- [net] fix recv return zero (Thomas Graf ) [452231 435657]- [misc] kernel crashes on futex (Anton Arapov ) [450336 435178]- [net] Fixing bonding rtnl_lock screwups (Fabio Olive Leite ) [451939 450219]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0612");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0612.html");
script_cve_id("CVE-2008-1294","CVE-2008-2136","CVE-2008-2812");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.10.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.10.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.10.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~92.1.10.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.10.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.10.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.10.0.1.el5debug~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~92.1.10.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

