# OpenVAS Vulnerability Test
# Description: Gentoo Linux security check
# $Id: glsa-201603-12.nasl 8032 2017-12-07 14:40:57Z teissa $

# Authors:
# Eero Volotinen <eero.volotinen@solinor.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.121454");
script_version("$Revision: 8032 $");
script_tag(name:"creation_date", value:"2016-03-14 15:52:48 +0200 (Mon, 14 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-12-07 15:40:57 +0100 (Thu, 07 Dec 2017) $");
script_name("Gentoo Linux Local Check: https://security.gentoo.org/glsa/201603-12");
script_tag(name: "insight", value: "Multiple format string vulnerabilities in FlightGear and SimGear allow user-assisted remote attackers to cause a denial of service and possibly execute arbitrary code via format string specifiers in certain data chunk values in an aircraft xml model."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://security.gentoo.org/glsa/201603-12");
script_cve_id("CVE-2012-2090","CVE-2012-2091");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
script_category(ACT_GATHER_INFO);
script_tag(name: "summary" , value: "Gentoo Linux Local Security Checks https://security.gentoo.org/glsa/201603-12");
script_copyright("Eero Volotinen");
script_family("Gentoo Local Security Checks");
exit(0);
}
include("revisions-lib.inc");

include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"games-simulation/flightgear", unaffected: make_list("ge 3.4.0"), vulnerable: make_list("lt 3.4.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"games-simulation/simgear", unaffected: make_list("ge 3.4.0"), vulnerable: make_list("lt 3.4.0"))) != NULL) {

  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
