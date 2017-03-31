# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-0382.nasl 4513 2016-11-15 09:37:48Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122509");
script_version("$Revision: 4513 $");
script_tag(name:"creation_date", value:"2015-10-08 14:46:56 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 10:37:48 +0100 (Tue, 15 Nov 2016) $");
script_name("Oracle Linux Local Check: ELSA-2009-0382");
script_tag(name: "insight", value: "ELSA-2009-0382 -  libvirt security update - [0.3.3-14.0.1.el5_3.1]- Replaced docs/redhat.gif in tarball[0.3.3-14.el5_3.1]- Add missing readonly checks for APIs (CVE-2008-5086)- Add missing buf check in proxy daemon (CVE-2009-0036)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-0382");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-0382.html");
script_cve_id("CVE-2008-5086","CVE-2009-0036");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_summary("Oracle Linux Local Security Checks ELSA-2009-0382");
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
  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.3.3~14.0.1.el5_3.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.3.3~14.0.1.el5_3.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.3.3~14.0.1.el5_3.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

