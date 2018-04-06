# OpenVAS Vulnerability Test
# $Id: deb_2711.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2711-1 using nvtgen 1.0
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

tag_affected  = "haproxy on Debian Linux";
tag_insight   = "HAProxy is a TCP/HTTP reverse proxy which is particularly suited for high
availability environments. It features connection persistence through HTTP
cookies, load balancing, header addition, modification, deletion both ways. It
has request blocking capabilities and provides interface to display server
status.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.4.8-1+squeeze1.

The stable distribution (wheezy) doesn't contain haproxy.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.24-1.

We recommend that you upgrade your haproxy packages.";
tag_summary   = "Multiple security issues have been found in HAProxy, a load-balancing
reverse proxy:

CVE-2012-2942 
Buffer overflow in the header capture code.

CVE-2013-1912 
Buffer overflow in the HTTP keepalive code.

CVE-2013-2175 
Denial of service in parsing HTTP headers.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892711");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-2175", "CVE-2013-1912", "CVE-2012-2942");
    script_name("Debian Security Advisory DSA 2711-1 (haproxy - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-06-19 00:00:00 +0200 (Wed, 19 Jun 2013)");
    script_tag(name: "cvss_base", value:"5.1");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2711.html");


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
if ((res = isdpkgvuln(pkg:"haproxy", ver:"1.4.8-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
