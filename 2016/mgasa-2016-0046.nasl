# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0046.nasl 5580 2017-03-15 10:00:34Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131214");
script_version("$Revision: 5580 $");
script_tag(name:"creation_date", value:"2016-02-08 19:55:20 +0200 (Mon, 08 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-03-15 11:00:34 +0100 (Wed, 15 Mar 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0046");
script_tag(name: "insight", value: "Gajim before 0.16.5 doesnt verify the origin of roster pushes thus allowing third parties to modify the roster via a man-in-the-middle attack (CVE-2015-8688)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0046.html");
script_cve_id("CVE-2015-8688");
script_tag(name:"cvss_base", value:"5.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0046");
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
if ((res = isrpmvuln(pkg:"gajim", rpm:"gajim~0.16.5~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"python-nbxmpp", rpm:"python-nbxmpp~0.5.3~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
