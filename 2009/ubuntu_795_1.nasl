# OpenVAS Vulnerability Test
# $Id: ubuntu_795_1.nasl 6639 2017-07-10 10:52:06Z cfischer $
# Description: Auto-generated from advisory USN-795-1 (nagios3)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 8.04 LTS:
  nagios2                         2.11-1ubuntu1.5

Ubuntu 8.10:
  nagios3                         3.0.2-1ubuntu1.2

Ubuntu 9.04:
  nagios3                         3.0.6-2ubuntu1.1

After a standard system upgrade you need to restart Nagios to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-795-1";

tag_insight = "It was discovered that Nagios did not properly parse certain commands
submitted using the WAP web interface. An authenticated user could exploit
this flaw and execute arbitrary programs on the server.";
tag_summary = "The remote host is missing an update to nagios3
announced via advisory USN-795-1.";

                                                                                


if(description)
{
 script_id(64368);
 script_version("$Revision: 6639 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 12:52:06 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
 script_cve_id("CVE-2009-2288");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-795-1 (nagios3)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"nagios2-common", ver:"2.11-1ubuntu1.5", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios2-doc", ver:"2.11-1ubuntu1.5", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios2-dbg", ver:"2.11-1ubuntu1.5", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios2", ver:"2.11-1ubuntu1.5", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3-common", ver:"3.0.2-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3-doc", ver:"3.0.2-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3-dbg", ver:"3.0.2-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3", ver:"3.0.2-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3-common", ver:"3.0.6-2ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3-doc", ver:"3.0.6-2ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3-dbg", ver:"3.0.6-2ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios3", ver:"3.0.6-2ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
