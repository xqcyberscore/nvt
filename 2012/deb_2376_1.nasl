# OpenVAS Vulnerability Test
# $Id: deb_2376_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2376-1 (ipmitool)
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
tag_insight = "It was discovered that OpenIPMI, the Intelligent Platform Management
Interface library and tools, used too wide permissions PID file,
which allows local users to kill arbitrary processes by writing to
this file.

For the stable distribution (squeeze), this problem has been fixed in
version 1.8.11-2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.11-5.

We recommend that you upgrade your ipmitool packages.";
tag_summary = "The remote host is missing an update to ipmitool
announced via advisory DSA 2376-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202376-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70693");
 script_tag(name:"cvss_base", value:"3.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
 script_cve_id("CVE-2011-4339");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:21:56 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2376-1 (ipmitool)");


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
if((res = isdpkgvuln(pkg:"ipmitool", ver:"1.8.11-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
