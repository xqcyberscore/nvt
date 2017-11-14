# OpenVAS Vulnerability Test
# Description: Gentoo Linux security check
# $Id: glsa-201512-06.nasl 7690 2017-11-08 06:26:20Z asteins $

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
script_oid("1.3.6.1.4.1.25623.1.0.121428");
script_version("$Revision: 7690 $");
script_tag(name:"creation_date", value:"2015-12-31 11:46:01 +0200 (Thu, 31 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-11-08 07:26:20 +0100 (Wed, 08 Nov 2017) $");
script_name("Gentoo Linux Local Check: https://security.gentoo.org/glsa/201512-06");
script_tag(name: "insight", value: "MPFR fails to adequately check user-supplied input, which could lead to a buffer overflow."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://security.gentoo.org/glsa/201512-06");
script_cve_id("CVE-2014-9474");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
script_category(ACT_GATHER_INFO);
script_summary("Gentoo Linux Local Security Checks https://security.gentoo.org/glsa/201512-06");
script_copyright("Eero Volotinen");
script_family("Gentoo Local Security Checks");
exit(0);
}
include("revisions-lib.inc");

include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-libs/mpfr", unaffected: make_list("ge 3.1.3_p4"), vulnerable: make_list("lt 3.1.3_p4"))) != NULL) {

  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
