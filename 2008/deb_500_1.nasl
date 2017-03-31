# OpenVAS Vulnerability Test
# $Id: deb_500_1.nasl 3983 2016-09-07 05:46:06Z teissa $
# Description: Auto-generated from advisory DSA 500-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Tatsuya Kinoshita discovered a vulnerability in flim, an emacs library
for working with internet messages, where temporary files were created
without taking appropriate precautions.  This vulnerability could
potentially be exploited by a local user to overwrite files with the
privileges of the user running emacs.  the 'chroot' option.

For the current stable distribution (woody) this problem has been
fixed in version 1.14.3-9woody1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you update your flim package.";
tag_summary = "The remote host is missing an update to flim
announced via advisory DSA 500-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20500-1";

if(description)
{
 script_id(53189);
 script_version("$Revision: 3983 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-07 07:46:06 +0200 (Wed, 07 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0422");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 500-1 (flim)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"flim", ver:"1.14.3-9woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
