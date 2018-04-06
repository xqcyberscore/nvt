# OpenVAS Vulnerability Test
# $Id: deb_2480_3.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2480-3 (request-tracker3.8)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The recent security updates for request-tracker3.8, DSA-2480-1 and
DSA-2480-2, contained another regression when running under mod_perl.

Please note that if you run request-tracker3.8 under the Apache web
server, you must stop and start Apache manually.  The restart
mechanism is not recommended, especially when using mod_perl.

For the stable distribution (squeeze), this problem has been fixed in
version 3.8.8-7+squeeze4.

We recommend that you upgrade your request-tracker3.8 packages.";
tag_summary = "The remote host is missing an update to request-tracker3.8
announced via advisory DSA 2480-3.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202480-3";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71465");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P"); 
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 02:57:14 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2480-3 (request-tracker3.8)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");
res = "";
report = "";
if((res = isdpkgvuln(pkg:"request-tracker3.8", ver:"3.8.8-7+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rt3.8-apache2", ver:"3.8.8-7+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rt3.8-clients", ver:"3.8.8-7+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rt3.8-db-mysql", ver:"3.8.8-7+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rt3.8-db-postgresql", ver:"3.8.8-7+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"rt3.8-db-sqlite", ver:"3.8.8-7+squeeze4", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
