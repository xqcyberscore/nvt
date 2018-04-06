# OpenVAS Vulnerability Test
# $Id: deb_2299_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2299-1 (ca-certificates)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "An unauthorized SSL certificate has been found in the wild issued
the DigiNotar Certificate Authority, obtained through a security
compromise with said company. Debian, like other software
distributors, has as a precaution decided to disable the DigiNotar
Root CA by default in its ca-certificates bundle.

For other software in Debian that ships a CA bundle, like the
Mozilla suite, updates are forthcoming.

For the oldstable distribution (lenny), the ca-certificates package
does not contain this root CA.

For the stable distribution (squeeze), the root CA has been
disabled starting ca-certificates version 20090814+nmu3.

For the testing distribution (wheezy) and unstable distribution
(sid), the root CA has been disabled starting ca-certificates
version 20110502+nmu1.

We recommend that you upgrade your ca-certificates packages.";
tag_summary = "The remote host is missing an update to ca-certificates
announced via advisory DSA 2299-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202299-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70234");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2299-1 (ca-certificates)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"ca-certificates", ver:"20090814+nmu3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
