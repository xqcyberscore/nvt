# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1019.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122118");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:23 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1019");
script_tag(name: "insight", value: "ELSA-2011-1019 -  libvirt security, bug fix, and enhancement update - [0.8.2-22.0.1.el5]- Replaced docs/et.png in tarball[libvirt-0.8.2-22.el5]- Fix auditing of disk hotunplug operations (rhbz#710151)[libvirt-0.8.2-21.el5]- remote: Protect against integer overflow (rhbz#717207)[0.8.2-20.el5]- Support enabling or disabling the HPET for Xen domains (rhbz#703193)- SMBIOS support (rhbz#661365)[0.8.2-19.el5]- xen: Plug memory leak in multiple serial ports support (rhbz#670789)- Manually kill gzip if restore fails before starting qemu (rhbz#681623)- qemu: Avoid double close on domain restore (rhbz#681623)- virterror: Avoid API breakage with vmware (rhbz#665075)- nwfilter: Resolve deadlock between VM ops and filter update (rhbz#697749)[0.8.2-18.el5]- xen: Prevent updating device when attaching a device (rhbz#662908)- Add PCI sysfs reset access (rhbz#689880)- xencapstest: Don't fail when Xen is installed (rhbz#690459)- Make error reporting in libvirtd thread safe (rhbz#690733)[0.8.2-17.el5]- Fix event-handling data race (rhbz#671569)- Add support for multiple serial ports into the Xen driver (rhbz#670789)- Add missing checks for read only connections (CVE-2011-1146)- Guess rhel macro based on dist macro (rhbz#665325)[0.8.2-16.el5]- Fix possible crash in virExec (rhbz#665549)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1019");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1019.html");
script_cve_id("CVE-2011-2511");
script_tag(name:"cvss_base", value:"4.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~22.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~22.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~22.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

