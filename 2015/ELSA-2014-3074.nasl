# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-3074.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123315");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:10 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-3074");
script_tag(name: "insight", value: "ELSA-2014-3074 - unbreakable enterprise kernel security bug fix update - [2.6.39-400.215.10]- auditsc: audit_krule mask accesses need bounds checking (Andy Lutomirski) [Orabug: 19590597] {CVE-2014-3917}[2.6.39-400.215.9]- oracleasm: Add support for new error return codes from block/SCSI (Martin K. Petersen) [Orabug: 18438934][2.6.39-400.215.8]- ib_ipoib: CSUM support in connected mode (Yuval Shaia) [Orabug: 18692878] - net: Reduce high cpu usage in bonding driver by do_csum (Venkat Venkatsubra) [Orabug: 18141731] - [random] Partially revert 6d7c7e49: random: make 'add_interrupt_randomness() (John Sobecki) [Orabug: 17740293] - oracleasm: claim FMODE_EXCL access on disk during asm_open (Srinivas Eeda) [Orabug: 19453460] - notify block layer when using temporary change to cache_type (Vaughan Cao) [Orabug: 19448451] - sd: Fix parsing of 'temporary ' cache mode prefix (Ben Hutchings) [Orabug: 19448451] - sd: fix array cache flushing bug causing performance problems (James Bottomley) [Orabug: 19448451] - block: fix max discard sectors limit (James Bottomley) [Orabug: 18961244] - xen-netback: fix deadlock in high memory pressure (Junxiao Bi) [Orabug: 18959416] - sdp: fix keepalive functionality (shamir rabinovitch) [Orabug: 18728784] - SELinux: Fix possible NULL pointer dereference in selinux_inode_permission() (Steven Rostedt) [Orabug: 18552029] - refcount: take rw_lock in ocfs2_reflink (Wengang Wang) [Orabug: 18406219] - ipv6: check return value for dst_alloc (Madalin Bucur) [Orabug: 17865160] - cciss: bug fix to prevent cciss from loading in kdump crash kernel (Mike Miller) [Orabug: 17740446] - configfs: fix race between dentry put and lookup (Junxiao Bi) [Orabug: 17627075]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-3074");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-3074.html");
script_cve_id("CVE-2014-3917");
script_tag(name:"cvss_base", value:"3.3");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.215.10.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.215.10.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.215.10.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.215.10.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.215.10.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.215.10.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.215.10.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.215.10.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.215.10.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.215.10.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.215.10.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.215.10.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

