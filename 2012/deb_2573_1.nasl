# OpenVAS Vulnerability Test
# $Id: deb_2573_1.nasl 2944 2016-03-24 09:32:58Z benallard $
# Description: Auto-generated from advisory DSA 2573-1 (radsecproxy)
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
tag_insight = "Ralf Paffrath reported that Radsecproxy, a RADIUS protocol proxy, mixed up
pre- and post-handshake verification of clients. This vulnerability may
wrongly accept clients without checking their certificate chain under
certain configurations.

Raphael Geissert spotted that the fix for CVE-2012-4523 was incomplete,
giving origin to CVE-2012-4566. Both vulnerabilities are fixed with this
update.

Notice that this fix may make Radsecproxy reject some clients that are
currently (erroneously) being accepted.

For the stable distribution (squeeze), these problems have been fixed in
version 1.4-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 1.6.2-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.6.2-1.

We recommend that you upgrade your radsecproxy packages.";
tag_summary = "The remote host is missing an update to radsecproxy
announced via advisory DSA 2573-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202573-1";

if(description)
{
 script_id(72568);
 script_cve_id("CVE-2012-4523", "CVE-2012-4566");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_version("$Revision: 2944 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 10:32:58 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-11-16 03:15:41 -0500 (Fri, 16 Nov 2012)");
 script_name("Debian Security Advisory DSA 2573-1 (radsecproxy)");


 script_summary("Debian Security Advisory DSA 2573-1 (radsecproxy)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
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
if((res = isdpkgvuln(pkg:"radsecproxy", ver:"1.4-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"radsecproxy", ver:"1.6.2-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
