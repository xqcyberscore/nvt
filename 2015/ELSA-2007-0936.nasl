# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0936.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122658");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:50:24 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0936");
script_tag(name: "insight", value: "ELSA-2007-0936 -  Important: kernel security update - [2.6.18-8.1.14.0.2.el5] - Fix bonding primary=ethX (Bert Barbe) [IT 101532] [ORA 5136660] - Add entropy module option to e1000/bnx2 (John Sobecki) [ORA 6045759] [2.6.18-8.1.14.el5] - Revert changes back to 2.6.18-8.1.10. - [x86_64] Zero extend all registers after ptrace in 32bit entry path (Anton Arapov ) [297871] {CVE-2007-4573} [2.6.18-8.1.12.el5] - [x86_64] Don't leak NT bit into next task (Dave Anderson ) [298151] {CVE-2007-4574} - [fs] Reset current->pdeath_signal on SUID binary execution (Peter Zijlstra ) [252307] {CVE-2007-3848} - [misc] Bounds check ordering issue in random driver (Anton Arapov ) [275961] {CVE-2007-3105} - [usb] usblcd: Locally triggerable memory consumption (Anton Arapov ) [276001] {CVE-2007-3513} - [x86_64] Zero extend all registers after ptrace in 32bit entry path (Anton Arapov ) [297871] {CVE-2007-4573} - [net] igmp: check for NULL when allocating GFP_ATOMIC skbs (Neil Horman ) [303281] [2.6.18-8.1.11.el5] - [xen] Guest access to MSR may cause system crash/data corruption (Bhavana Nagendra ) [253312] {CVE-2007-3733} - [dlm] A TCP connection to DLM port blocks DLM operations (Patrick Caulfield ) [245922] {CVE-2007-3380} - [ppc] 4k page mapping support for userspace in 64k kernels (Scott Moser ) [275841] {CVE-2007-3850} - [ptrace] NULL pointer dereference triggered by ptrace (Anton Arapov ) [275981] {CVE-2007-3731} - [fs] hugetlb: fix prio_tree unit (Konrad Rzeszutek ) [253929] {CVE-2007-4133}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0936");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0936.html");
script_cve_id("CVE-2007-4573");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~8.1.14.0.2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~8.1.14.0.2.el5~1.2.6~6.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~8.1.14.0.2.el5PAE~1.2.6~6.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~8.1.14.0.2.el5xen~1.2.6~6.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~8.1.14.0.2.el5~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~8.1.14.0.2.el5PAE~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~8.1.14.0.2.el5xen~2.0.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

