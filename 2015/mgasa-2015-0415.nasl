# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0415.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131105");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-27 12:54:48 +0200 (Tue, 27 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0415");
script_tag(name: "insight", value: "A vulnerability in the Oracle VM VirtualBox component prior to 4.0.34, 4.1.42, 4.2.34, 4.3.32 and 5.0.8. Easily exploitable vulnerability requiring logon to Operating System. Successful attack of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS). Note: Only Windows guests are impacted, and Windows guests without VirtualBox Guest Additions installed are not affected (CVE-2015-4813). A vulnerability in the Oracle VM VirtualBox component prior to 4.0.34, 4.1.42, 4.2.34, 4.3.32 and 5.0.8. Easily exploitable vulnerability allows successful unauthenticated network attacks. Successful attack of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS). Note: Only VMs with Remote Display feature (RDP) enabled are impacted (CVE-2015-4896). For other fixes in this update, see the referenced changelog."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0415.html");
script_cve_id("CVE-2015-4813","CVE-2015-4896");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0415");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.0.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.0.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.0.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
