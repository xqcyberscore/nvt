# OpenVAS Vulnerability Test
# $Id: deb_2651.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2651-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_affected  = "smokeping on Debian Linux";
tag_insight   = "SmokePing consists of a daemon process which organizes the
latency measurements and a CGI which presents the graphs.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 2.3.6-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 2.6.7-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.7-1.

We recommend that you upgrade your smokeping packages.";
tag_summary   = "A cross-site scripting vulnerability was discovered in smokeping, a
latency logging and graphing system. Input passed to the displaymode 

parameter was not properly sanitized. An attacker could use this flaw to
execute arbitrary HTML and script code in a user's browser session in
the context of an affected site.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892651");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-0790");
    script_name("Debian Security Advisory DSA 2651-1 (smokeping - cross-site scripting vulnerability)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-03-20 00:00:00 +0100 (Wed, 20 Mar 2013)");
    script_tag(name: "cvss_base", value:"4.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2651.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"smokeping", ver:"2.3.6-5+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smokeping", ver:"2.6.7-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
