# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0627.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122328");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:16:54 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0627");
script_tag(name: "insight", value: "ELSA-2010-0627 -  kvm security and bug fix update - [kvm-83-164.0.1.el5_5.21]- Added kvm-add-oracle-workaround-for-libvirt-bug.patch- Added kvm-Introduce-oel-machine-type.patch[kvm-83-164.el5_5.21]- kvm-Fix-segfault-in-mmio-subpage-handling-code.patch [bz#619412]- Resolves: bz#619412 (CVE-2010-2784 qemu: insufficient constraints checking in exec.c:subpage_register() [rhel-5.5.z])[kvm-83-164.el5_5.20]- kvm-virtio-net-correct-packet-length-checks.patch [bz#610343]- Resolves: bz#610343 (Virtio: Transfer file caused guest in same vlan abnormally quit)[kvm-83-164.el5_5.19]- kvm-qcow2-Fix-qemu-img-check-segfault-on-corrupted-image.patch [bz#610342]- kvm-qcow2-Don-t-try-to-check-tables-that-couldn-t-be-loa.patch [bz#610342]- kvm-qemu-img-check-Distinguish-different-kinds-of-errors.patch [bz#618206]- kvm-qcow2-Change-check-to-distinguish-error-cases.patch [bz#618206]- Resolves: bz#610342 ([kvm] segmentation fault when running qemu-img check on faulty image)- Resolves: bz#618206 ([kvm] qemu image check returns cluster errors when using virtIO block (thinly provisioned) during e_no_space events (along with EIO errors))[kvm-83-164.el5_5.18]- kvm-New-slots-need-dirty-tracking-enabled-when-migrating.patch [bz#618205]- Resolves: bz#618205 (SPICE - race in KVM/Spice would cause migration to fail (slots are not registered properly?))[kvm-83-164.el5_5.17]- kvm-kernel-KVM-MMU-fix-conflict-access-permissions-in-direct-sp.patch [bz#616796]- Resolves: bz#616796 (KVM uses wrong permissions for large guest pages)[kvm-83-164.el5_5.16]- kvm-kernel-fix-null-pointer-dereference.patch [bz#570531] - Resolves: bz#570531 - CVE: CVE-2010-0435- kvm-qemu-fix-unsafe-ring-handling.patch [bz#568816] - Resolves: bz#568816 - CVE: CVE-2010-0431"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0627");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0627.html");
script_cve_id("CVE-2010-0431","CVE-2010-0435","CVE-2010-2784");
script_tag(name:"cvss_base", value:"6.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~164.0.1.el5_5.21", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~164.0.1.el5_5.21", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~164.0.1.el5_5.21", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~164.0.1.el5_5.21", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

