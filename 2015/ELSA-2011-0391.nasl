# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0391.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122206");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:47 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0391");
script_tag(name: "insight", value: "ELSA-2011-0391 -  libvirt security update - [0.8.1-27.0.1.el6_0.5]- Replace docs/et.png in tarball with blank image[0.8.1-27.el6_0.5]- Properly report error in virConnectDomainXMLToNative (CVE-2011-1146)[0.8.1-27.el6_0.4]- Add missing checks for read-only connections (CVE-2011-1146)[0.8.1-27.el6_0.3]- Remove patches not suitable for proper Z-stream: - Export host information through SMBIOS to guests (rhbz#652678) - Support forcing a CDROM eject (rhbz#658147)- Plug several memory leaks (rhbz#672549)- Avoid memory overhead of matchpathcon (rhbz#672554)- Do not start libvirt-guests if that service is off (rhbz#668694)[0.8.1-27.el6_0.2]- spec file cleanups (rhbz#662045)- Fix deadlock on concurrent multiple bidirectional migration (rhbz#662043)- Fix off-by-one error in clock-variable (rhbz#662046)- Export host information through SMBIOS to guests (rhbz#652678)- Ensure device is deleted from guest after unplug (rhbz#662041)- Distinguish between QEMU domain shutdown and crash (rhbz#662042)[0.8.1-27.el6_0.1]- Fix JSON migrate_set_downtime command (rhbz#658143)- Make SASL work over UNIX domain sockets (rhbz#658144)- Let qemu group look below /var/lib/libvirt/qemu/ (rhbz#656972)- Fix save/restore on root_squashed NFS (rhbz#656355)- Fix race on multiple migration (rhbz#658141)- Export host information through SMBIOS to guests (rhbz#652678)- Support forcing a CDROM eject (rhbz#658147)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0391");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0391.html");
script_cve_id("CVE-2011-1146");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~15.0.1.el5_6.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~15.0.1.el5_6.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~15.0.1.el5_6.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

