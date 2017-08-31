# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-2015.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122177");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:18 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-2015");
script_tag(name: "insight", value: "ELSA-2011-2015 -  Oracle Linux 6 Unbreakable Enterprise kernel security fix update - [2.6.32-100.28.15.el6]- sctp: fix to calc the INIT/INIT-ACK chunk length correctly is set {CVE-2011-1573}- dccp: fix oops on Reset after close {CVE-2011-1093}- bridge: netfilter: fix information leak {CVE-2011-1080}- Bluetooth: bnep: fix buffer overflow {CVE-2011-1079}- net: don't allow CAP_NET_ADMIN to load non-netdev kernel modules {CVE-2011-1019}- ipip: add module alias for tunl0 tunnel device- gre: add module alias for gre0 tunnel device- drm/radeon/kms: check AA resolve registers on r300 {CVE-2011-1016}- drm/radeon: fix regression with AA resolve checking {CVE-2011-1016}- drm: fix unsigned vs signed comparison issue in modeset ctl ioctl {CVE-2011-1013}- proc: protect mm start_code/end_code in /proc/pid/stat {CVE-2011-0726}- ALSA: caiaq - Fix possible string-buffer overflow {CVE-2011-0712}- xfs: zero proper structure size for geometry calls {CVE-2011-0711}- xfs: prevent leaking uninitialized stack memory in FSGEOMETRY_V1 {CVE-2011-0711}- ima: fix add LSM rule bug {CVE-2011-0006}- IB/uverbs: Handle large number of entries in poll CQ {CVE-2010-4649, CVE-2011-1044}- CAN: Use inode instead of kernel address for /proc file {CVE-2010-4565}[2.6.32-100.28.14.el6]- IB/qib: fix qib compile warning.- IB/core: Allow device-specific per-port sysfs files.- dm crypt: add plain64 iv.- firmware: add firmware for qib.- Infiniband: Add QLogic PCIe QLE InfiniBand host channel adapters support."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-2015");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-2015.html");
script_cve_id("CVE-2010-4565","CVE-2010-4649","CVE-2011-0006","CVE-2011-0711","CVE-2011-0712","CVE-2011-0726","CVE-2011-1013","CVE-2011-1016","CVE-2011-1019","CVE-2011-1044","CVE-2011-1079","CVE-2011-1080","CVE-2011-1093","CVE-2011-1573");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~100.28.15.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~100.28.15.el5~1.5.1~4.0.28", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~100.28.15.el5debug~1.5.1~4.0.28", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~100.28.15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

