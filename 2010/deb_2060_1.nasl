# OpenVAS Vulnerability Test
# $Id: deb_2060_1.nasl 5245 2017-02-09 08:57:08Z teissa $
# Description: Auto-generated from advisory DSA 2060-1 (cacti)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Stefan Esser discovered that cacti, a front-end to rrdtool for monitoring
systems and services, is not properly validating input passed to the rra_id
parameter of the graph.php script.  Due to checking the input of $_REQUEST
but using $_GET input in a query an unauthenticated attacker is able to
perform SQL injections via a crafted rra_id $_GET value and an additional
valid rra_id $_POST or $_COOKIE value.


For the stable distribution (lenny), this problem has been fixed in
version 0.8.7b-2.1+lenny3.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7e-4.


We recommend that you upgrade your cacti packages.";
tag_summary = "The remote host is missing an update to cacti
announced via advisory DSA 2060-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202060-1";


if(description)
{
 script_id(67631);
 script_version("$Revision: 5245 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-09 09:57:08 +0100 (Thu, 09 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2092");
 script_name("Debian Security Advisory DSA 2060-1 (cacti)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"cacti", ver:"0.8.7b-2.1+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
