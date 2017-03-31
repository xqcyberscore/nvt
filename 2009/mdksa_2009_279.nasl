# OpenVAS Vulnerability Test
# $Id: mdksa_2009_279.nasl 4989 2017-01-11 16:57:11Z teissa $
# Description: Auto-generated from advisory MDVSA-2009:279 (ocaml-mysql)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "A vulnerability has been found and corrected in ocaml-mysql:

It was discovered that mysql-ocaml, OCaml bindings for MySql,
was missing a function to call mysql_real_escape_string(). This
is needed, because mysql_real_escape_string() honours the charset
of the connection and prevents insufficient escaping, when certain
multibyte character encodings are used. The added function is called
real_escape() and takes the established database connection as a first
argument. The old escape_string() was kept for backwards compatibility
(CVE-2009-2942).

This update fixes this vulnerability.

Affected: Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:279
http://www.debian.org/security/2009/dsa-1910";
tag_summary = "The remote host is missing an update to ocaml-mysql
announced via advisory MDVSA-2009:279.";

                                                                                

if(description)
{
 script_id(66035);
 script_version("$Revision: 4989 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-11 17:57:11 +0100 (Wed, 11 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2009-2942");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:279 (ocaml-mysql)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ocaml-mysql", rpm:"ocaml-mysql~1.0.4~9.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ocaml-mysql-devel", rpm:"ocaml-mysql-devel~1.0.4~9.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
