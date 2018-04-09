# OpenVAS Vulnerability Test
# Description: Gentoo Linux security check
# $Id: glsa-201502-13.nasl 9374 2018-04-06 08:58:12Z cfischer $

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
script_oid("1.3.6.1.4.1.25623.1.0.121352");
script_version("$Revision: 9374 $");
script_tag(name:"creation_date", value:"2015-09-29 11:28:34 +0300 (Tue, 29 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:58:12 +0200 (Fri, 06 Apr 2018) $");
script_name("Gentoo Linux Local Check: https://security.gentoo.org/glsa/201502-13");
script_tag(name: "insight", value: "Multiple vulnerabilities have been discovered in Chromium. Please review the CVE identifiers referenced below for details."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://security.gentoo.org/glsa/201502-13");
script_cve_id("CVE-2014-7923","CVE-2014-7924","CVE-2014-7925","CVE-2014-7926","CVE-2014-7927","CVE-2014-7928","CVE-2014-7929","CVE-2014-7930","CVE-2014-7931","CVE-2014-7932","CVE-2014-7933","CVE-2014-7934","CVE-2014-7935","CVE-2014-7936","CVE-2014-7937","CVE-2014-7938","CVE-2014-7939","CVE-2014-7940","CVE-2014-7941","CVE-2014-7942","CVE-2014-7943","CVE-2014-7944","CVE-2014-7945","CVE-2014-7946","CVE-2014-7947","CVE-2014-7948","CVE-2014-9646","CVE-2014-9647","CVE-2014-9648","CVE-2015-1205","CVE-2015-1209","CVE-2015-1210","CVE-2015-1211","CVE-2015-1212","CVE-2015-1346","CVE-2015-1359","CVE-2015-1360","CVE-2015-1361");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Gentoo Linux Local Security Checks https://security.gentoo.org/glsa/201502-13");
script_copyright("Eero Volotinen");
script_family("Gentoo Local Security Checks");
exit(0);
}
include("revisions-lib.inc");

include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 40.0.2214.111"), vulnerable: make_list("lt 40.0.2214.111"))) != NULL) {

  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
