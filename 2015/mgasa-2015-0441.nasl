# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0441.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131128");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-11-11 09:58:16 +0200 (Wed, 11 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0441");
script_tag(name: "insight", value: "Federico Scrinzi discovered that LibreOffice incorrectly handled documents inserted into Writer or Calc via links. If a user were tricked into opening a specially crafted document, a remote attacker could possibly obtain the contents of arbitrary files (CVE-2015-4551). It was discovered that LibreOffice incorrectly handled PrinterSetup data stored in ODF files. If a user were tricked into opening a specially crafted ODF document, a remote attacker could cause LibreOffice to crash, and possibly execute arbitrary code.(CVE-2015-5212). It was discovered that LibreOffice incorrectly handled the number of pieces in DOC files. If a user were tricked into opening a specially crafted DOC document, a remote attacker could cause LibreOffice to crash, and possibly execute arbitrary code (CVE-2015-5213). It was discovered that LibreOffice incorrectly handled bookmarks in DOC files. If a user were tricked into opening a specially crafted DOC document, a remote attacker could cause LibreOffice to crash, and possibly execute arbitrary code (CVE-2015-5214). LibreOffice has been updated to version 4.4.6, which fixes these issues as well as several other bugs."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0441.html");
script_cve_id("CVE-2015-4551","CVE-2015-5212","CVE-2015-5213","CVE-2015-5214");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0441");
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
if ((res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~4.4.6.3~2.2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
