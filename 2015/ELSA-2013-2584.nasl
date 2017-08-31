# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-2584.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123512");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:53 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-2584");
script_tag(name: "insight", value: "ELSA-2013-2584 - Unbreakable Enterprise Kernel security update - [2.6.39-400.211.2]- fs/compat_ioctl.c: VIDEO_SET_SPU_PALETTE missing error check (Kees Cook) [Orabug: 17842208] {CVE-2013-1928}- Bluetooth: RFCOMM - Fix info leak via getsockname() (Mathias Krause) [Orabug: 17842129] {CVE-2012-6545}- Bluetooth: RFCOMM - Fix info leak in ioctl(RFCOMMGETDEVLIST) (Mathias Krause) [Orabug: 17842105] {CVE-2012-6545}- llc: Fix missing msg_namelen update in llc_ui_recvmsg() (Mathias Krause) [Orabug: 17842095] {CVE-2013-3231}- HID: pantherlord: validate output report details (Kees Cook) [Orabug: 17842084] {CVE-2013-2892}- HID: zeroplus: validate output report details (Kees Cook) [Orabug: 17842081] {CVE-2013-2889}- HID: provide a helper for validating hid reports (Kees Cook) [Orabug: 17842081] {CVE-2013-2889}- KVM: Fix iommu map/unmap to handle memory slot moves (Jerry Snitselaar) [Orabug: 17842075] {CVE-2013-4592}- ansi_cprng: Fix off by one error in non-block size request (Jerry Snitselaar) [Orabug: 17842072] {CVE-2013-4345}- HID: validate HID report id size (Kees Cook) [Orabug: 17842063] {CVE-2013-2888}- ipv6: remove max_addresses check from ipv6_create_tempaddr (Hannes Frederic Sowa) [Orabug: 17842056] {CVE-2013-0343}- ipv6: udp packets following an UFO enqueued packet need also be handled by UFO (Hannes Frederic Sowa) [Orabug: 17842050] {CVE-2013-4387}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-2584");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-2584.html");
script_cve_id("CVE-2012-6545","CVE-2013-3231","CVE-2013-0343","CVE-2013-4345","CVE-2013-1928","CVE-2013-2888","CVE-2013-2889","CVE-2013-2892","CVE-2013-4387","CVE-2013-4592");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.211.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.211.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.211.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.211.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.211.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.211.2.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.211.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.211.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.211.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.211.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.211.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.211.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

