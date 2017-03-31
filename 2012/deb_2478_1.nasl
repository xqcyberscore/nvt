# OpenVAS Vulnerability Test
# $Id: deb_2478_1.nasl 2944 2016-03-24 09:32:58Z benallard $
# Description: Auto-generated from advisory DSA 2478-1 (sudo)
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
tag_insight = "It was discovered that sudo misparsed network masks used in Host and
Host_List stanzas. This allowed the execution of commands on hosts,
where the user would not be allowed to run the specified command.

For the stable distribution (squeeze), this problem has been fixed in
version 1.7.4p4-2.squeeze.3.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your sudo packages.";
tag_summary = "The remote host is missing an update to sudo
announced via advisory DSA 2478-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202478-1";

if(description)
{
 script_id(71356);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-2337");
 script_version("$Revision: 2944 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 10:32:58 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:51:43 -0400 (Thu, 31 May 2012)");
 script_name("Debian Security Advisory DSA 2478-1 (sudo)");


 script_summary("Debian Security Advisory DSA 2478-1 (sudo)");

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
if((res = isdpkgvuln(pkg:"sudo", ver:"1.7.4p4-2.squeeze.3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.7.4p4-2.squeeze.3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
