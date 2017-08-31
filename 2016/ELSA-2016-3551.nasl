# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-3551.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.fi
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.122928");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-05-09 14:24:45 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-3551");
script_tag(name: "insight", value: "ELSA-2016-3551 - Unbreakable Enterprise kernel security update - kernel-uek[3.8.13-118.6.1]- skbuff: skb_segment: orphan frags before copying (Dongli Zhang) [Orabug: 23018911] - RDS/IB: VRPC DELAY / OSS RECONNECT CAUSES 5 MINUTE STALL ON PORT FAILURE (Venkat Venkatsubra) [Orabug: 22888920] - mlx4_core: Introduce restrictions for PD update (Ajaykumar Hotchandani) - filename should be destroyed via final_putname() instead of __putname() (John Sobecki) [Orabug: 22346320] - RDS: Fix the atomicity for congestion map update (Wengang Wang) [Orabug: 23141554] - sctp: Prevent soft lockup when sctp_accept() is called during a timeout event (Karl Heiss) [Orabug: 23222753] {CVE-2015-8767}[3.8.13-118.5.1]- x86_64: expand kernel stack to 16K (Minchan Kim) [Orabug: 21140371] - iommu/vt-d: add quirk for broken interrupt remapping on 55XX chipsets (Neil Horman) [Orabug: 22534160] - xen: remove unneeded variables and one constant (Daniel Kiper) [Orabug: 22288700] - Revert 'x86/xen: delay construction of mfn_list_list' (Daniel Kiper) [Orabug: 22288700] - ocfs2/dlm: fix misuse of list_move_tail() in dlm_run_purge_list() (Tariq Saeed) [Orabug: 22898384] - ocfs2/dlm: do not purge lockres that is queued for assert master (Xue jiufei) [Orabug: 22898384]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-3551");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-3551.html");
script_cve_id("CVE-2015-8767");
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
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~118.6.1.el7uek~0.4.5~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.6.1.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.6.1.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.6.1.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.6.1.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.6.1.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.6.1.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~118.6.1.el6uek~0.4.5~3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.6.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.6.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.6.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.6.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.6.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.6.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

