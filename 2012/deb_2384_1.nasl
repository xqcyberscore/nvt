# OpenVAS Vulnerability Test
# $Id: deb_2384_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2384-1 (cacti)
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
tag_insight = "Several vulnerabilities have been discovered in cacti, a graphing tool
for monitoring data. Multiple cross site scripting issues allow remote
attackers to inject arbitrary web script or HTML. An SQL injection
vulnerability allows remote attackers to execute arbitrary SQL commands.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.8.7b-2.1+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.7g-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7i-2.

We recommend that you upgrade your cacti packages.";
tag_summary = "The remote host is missing an update to cacti
announced via advisory DSA 2384-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202384-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70703");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1644", "CVE-2010-1645", "CVE-2010-2543", "CVE-2010-2545", "CVE-2011-4824");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:26:57 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2384-1 (cacti)");


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
if((res = isdpkgvuln(pkg:"cacti", ver:"0.8.7b-2.1+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"cacti", ver:"0.8.7g-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
