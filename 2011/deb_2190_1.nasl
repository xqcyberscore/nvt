# OpenVAS Vulnerability Test
# $Id: deb_2190_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2190-1 (wordpress)
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
tag_insight = "Two XSS bugs and one potential information disclosure issue were discovered
in wordpress, a weblog manager.
The Common Vulnerabilities and Exposures project identifies the
following problems:


CVE-2011-0700

Input passed via the post title when performing a Quick Edit or Bulk Edit
action and via the post_status, comment_status, and ping_status
parameters is not properly sanitised before being used.
Certain input passed via tags in the tags meta-box is not properly sanitised
before being returned to the user.


CVE-2011-0701

Wordpress incorrectly enforces user access restrictions when accessing posts
via the media uploader and can be exploited to disclose the contents
of e.g. private or draft posts.


The oldstable distribution (lenny) is not affected by these problems.

For the stable distribution (squeeze), these problems have been fixed in
version 3.0.5+dfsg-0+squeeze1

For the testing distribution (wheezy), and the unstable distribution (sid),
these problems have been fixed in version 3.0.5+dfsg-1

We recommend that you upgrade your wordpress packages.";
tag_summary = "The remote host is missing an update to wordpress
announced via advisory DSA 2190-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202190-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69326");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_cve_id("CVE-2011-0700", "CVE-2011-0701");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 2190-1 (wordpress)");



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
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.0.5+dfsg-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.0.5+dfsg-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress", ver:"3.0.5+dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.0.5+dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
