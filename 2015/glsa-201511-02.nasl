# OpenVAS Vulnerability Test
# Description: Gentoo Linux security check
# $Id: glsa-201511-02.nasl 9374 2018-04-06 08:58:12Z cfischer $

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
script_oid("1.3.6.1.4.1.25623.1.0.121422");
script_version("$Revision: 9374 $");
script_tag(name:"creation_date", value:"2015-11-17 17:06:23 +0200 (Tue, 17 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:58:12 +0200 (Fri, 06 Apr 2018) $");
script_name("Gentoo Linux Local Check: https://security.gentoo.org/glsa/201511-02");
script_tag(name: "insight", value: "Multiple vulnerabilities have been discovered in Adobe Flash Player. Please review the CVE identifiers referenced below for details."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://security.gentoo.org/glsa/201511-02");
script_cve_id("CVE-2015-5569","CVE-2015-7625","CVE-2015-7626","CVE-2015-7627","CVE-2015-7628","CVE-2015-7629","CVE-2015-7630","CVE-2015-7631","CVE-2015-7632","CVE-2015-7633","CVE-2015-7634","CVE-2015-7643","CVE-2015-7644","CVE-2015-7645","CVE-2015-7646","CVE-2015-7647","CVE-2015-7648","CVE-2015-7651","CVE-2015-7652","CVE-2015-7653","CVE-2015-7654","CVE-2015-7655","CVE-2015-7656","CVE-2015-7657","CVE-2015-7658","CVE-2015-7659","CVE-2015-7660","CVE-2015-7661","CVE-2015-7662","CVE-2015-7663","CVE-2015-8042","CVE-2015-8043","CVE-2015-8044","CVE-2015-8046");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Gentoo Linux Local Security Checks https://security.gentoo.org/glsa/201511-02");
script_copyright("Eero Volotinen");
script_family("Gentoo Local Security Checks");
exit(0);
}
include("revisions-lib.inc");

include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-plugins/adobe-flash", unaffected: make_list("ge 11.2.202.548"), vulnerable: make_list("lt 11.2.202.548"))) != NULL) {

  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
