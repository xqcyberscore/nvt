# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0127.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123749");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0127");
script_tag(name: "insight", value: "ELSA-2013-0127 -  libvirt security and bug fix update - [0.8.2-29.0.1.el5] - Replaced docs/et.png in tarball - remove virshtest from test cases to fix failure in mock build root [libvirt-0.8.2-29.el5] - Coverity pointed out an use after free in the fix for 816601 (rhbz#772848) [libvirt-0.8.2-28.el5] - qemu: Rollback on used USB devices (rhbz#816601) - qemu: Don't delete USB device on failed qemuPrepareHostdevUSBDevices (rhbz#816601) [libvirt-0.8.2-27.el5] - qemu: Delete USB devices used by domain on stop (rhbz#816601) [libvirt-0.8.2-26.el5] - Fix off-by-1 in virFileAbsPath. (rhbz#680289) - Fix autostart flag when loading running domains (rhbz#675319) - node_device: Avoid null dereference on error (rhbz#772848) - util: Avoid null deref on qcowXGetBackingStore (rhbz#772848) - docs: Improve virsh domxml-*-native command docs (rhbz#783001) - Clarify the purpose of domxml-from-native (rhbz#783001) - qemu: Add return value check (rhbz#772821) - storage: Avoid mishandling backing store > 2GB (rhbz#772821) - util: Avoid PATH_MAX-sized array (rhbz#816601) - qemu: Keep list of USB devices attached to domains (rhbz#816601) - qemu: Don't leak temporary list of USB devices (rhbz#816601) - usb: Create functions to search usb device accurately (rhbz#816601) - qemu: Call usb search function for hostdev initialization and hotplug (rhbz#816601) - usb: Fix crash when failing to attach a second usb device (rhbz#816601)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0127");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0127.html");
script_cve_id("CVE-2012-2693");
script_tag(name:"cvss_base", value:"3.7");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~29.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~29.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~29.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

