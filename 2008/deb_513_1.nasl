# OpenVAS Vulnerability Test
# $Id: deb_513_1.nasl 3983 2016-09-07 05:46:06Z teissa $
# Description: Auto-generated from advisory DSA 513-1
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
tag_insight = "jaguar@felinemenace.org discovered a format string vulnerability in
log2mail, whereby a user able to log a specially crafted message to a
logfile monitored by log2mail (for example, via syslog) could cause
arbitrary code to be executed with the privileges of the log2mail
process.  By default, this process runs as user 'log2mail', which is a
member of group 'adm' (which has access to read system logfiles).

CVE-2004-0450: log2mail format string vulnerability via syslog(3) in
printlog()

For the current stable distribution (woody), this problem has been
fixed in version 0.2.5.2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you update your log2mail package.";
tag_summary = "The remote host is missing an update to log2mail
announced via advisory DSA 513-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20513-1";

if(description)
{
 script_id(53204);
 script_version("$Revision: 3983 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-07 07:46:06 +0200 (Wed, 07 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(10460);
 script_cve_id("CVE-2004-0450");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 513-1 (log2mail)");



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
if ((res = isdpkgvuln(pkg:"log2mail", ver:"0.2.5.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
