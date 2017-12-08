# OpenVAS Vulnerability Test
# Description: Gentoo Linux security check
# $Id: glsa-201601-05.nasl 8029 2017-12-07 12:38:42Z teissa $

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
script_oid("1.3.6.1.4.1.25623.1.0.121439");
script_version("$Revision: 8029 $");
script_tag(name:"creation_date", value:"2016-02-01 06:56:31 +0200 (Mon, 01 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-12-07 13:38:42 +0100 (Thu, 07 Dec 2017) $");
script_name("Gentoo Linux Local Check: https://security.gentoo.org/glsa/201601-05");
script_tag(name: "insight", value: "Multiple vulnerabilities have been discovered in OpenSSL. Please review the upstream advisory and CVE identifiers referenced below for details."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://security.gentoo.org/glsa/201601-05");
script_cve_id("CVE-2015-3197","CVE-2016-0701");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
script_category(ACT_GATHER_INFO);
script_tag(name: "summary" , value: "Gentoo Linux Local Security Checks https://security.gentoo.org/glsa/201601-05");
script_copyright("Eero Volotinen");
script_family("Gentoo Local Security Checks");
exit(0);
}
include("revisions-lib.inc");

include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-libs/openssl", unaffected: make_list("ge 1.0.2f"), vulnerable: make_list("lt 1.0.2f"))) != NULL) {

  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
