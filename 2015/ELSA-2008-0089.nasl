# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0089.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122613");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:49:20 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0089");
script_tag(name: "insight", value: "ELSA-2008-0089 -  Important: kernel security and bug fix update - [2.6.18-53.1.6.0.1.el5] - [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [ORA 6045759] - [NET] Fix msi issue with kexec/kdump (Michael Chan) [ORA 6219364] - [MM] Fix alloc_pages_node() static `nid race made kernel crash (Joe Jin) [ORA 6187457] - [splice] Fix bad unlock_page() in error case (Jens Axboe) [ORA 6263574] - [dio] fix error-path crashes (Linux Torvalds) [ORA 6242289] - [MM] Fix leak in hugepages, regression for shared pagetables patch (Adam Litke) [ORABUG 6732368] [2.6.18-53.1.6.el5] - [fs] corruption by unprivileged user in directories (Vitaly Mayatskikh ) [428796] {CVE-2008-0001} [2.6.18-53.1.5.el5] - [ia64] ptrace: access to user register backing (Roland McGrath ) [259801] - [fs] cifs: buffer overflow due to corrupt response (Jeff Layton ) [372991] - [net] s2io: correct VLAN frame reception (Andy Gospodarek ) [426289] - [net] s2io: allow VLAN creation on interfaces (Andy Gospodarek ) [426289] - [misc] tux: get rid of O_ATOMICLOOKUP (Michal Schmidt ) [426494] - [x86_64] fix race conditions in setup_APIC_timer (Geoff Gustafson ) [424181] - [fs] core dump file ownership (Don Howard ) [396991] - [nfs] let rpciod finish sillyrename then umount (Steve Dickson ) [414041] - [nfs] fix a race in silly rename (Steve Dickson ) [414041] - [nfs] clean up the silly rename code (Steve Dickson ) [414041] - [nfs] infrastructure changes for silly renames (Steve Dickson ) [414041] - [nfs] introduce nfs_removeargs and nfs_removeres (Steve Dickson ) [414041] - [ia64] remove stack hard limit (Aron Griffis ) [412091] - [fs] sysfs: fix race condition around sd->s_dentry (Eric Sandeen ) [245777] {CVE-2007-3104} - [fs] sysfs: fix condition check in sysfs_drop_dentry() (Eric Sandeen ) [245777] {CVE-2007-3104} - [fs] sysfs: store inode nrs in s_ino (Eric Sandeen ) [245777] {CVE-2007-3104} - [xen] ia64: vulnerability of copy_to_user in PAL emu (Jarod Wilson ) [425938]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0089");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0089.html");
script_cve_id("CVE-2007-3104","CVE-2007-5904","CVE-2007-6206","CVE-2007-6416","CVE-2008-0001");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~53.1.6.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~53.1.6.0.1.el5~1.2.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~53.1.6.0.1.el5PAE~1.2.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~53.1.6.0.1.el5xen~1.2.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~53.1.6.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~53.1.6.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~53.1.6.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

