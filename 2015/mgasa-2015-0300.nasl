# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0300.nasl 7390 2017-10-10 07:15:36Z asteins $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130078");
script_version("$Revision: 7390 $");
script_tag(name:"creation_date", value:"2015-10-15 10:42:27 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-10-10 09:15:36 +0200 (Tue, 10 Oct 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0300");
script_tag(name: "insight", value: "JSON error responses from the IPython notebook REST API contained URL parameters and were incorrectly reported as text/html instead of application/json. The error messages included some of these URL params, resulting in a cross site scripting attack (CVE-2015-4707). POST requests exposed via the IPython REST API are vulnerable to cross-site request forgery (CSRF). Web pages on different domains can make non-AJAX POST requests to known IPython URLs, and IPython will honor them. The user's browser will automatically send IPython cookies along with the requests. The response is blocked by the Same-Origin Policy, but the request isn't (CVE-2015-5607). The Mageia 5 package has been patched to fix these issues. The Mageia 4 package wasn't vulnerable to CVE-2015-4707, but it has been updated and patched to fix CVE-2015-5607."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0300.html");
script_cve_id("CVE-2015-4707","CVE-2015-5607");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0300");
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
if ((res = isrpmvuln(pkg:"ipython", rpm:"ipython~2.3.0~2.2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
