# OpenVAS Vulnerability Test
# $Id: deb_2832.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2832-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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

tag_affected  = "memcached on Debian Linux";
tag_insight   = "Danga Interactive developed memcached to enhance the speed of LiveJournal.com,
a site which was already doing 20 million+ dynamic page views per day for 1
million users with a bunch of webservers and a bunch of database servers.
memcached dropped the database load to almost nothing, yielding faster page
load times for users, better resource utilization, and faster access to the
databases on a memcache miss.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed
in version 1.4.5-1+deb6u1. Note that the patch for CVE-2013-7239 was not
applied for the oldstable distribution as SASL support is not enabled in
this version. This update also provides the fix for CVE-2013-0179 
which
was fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.13-0.2+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your memcached packages.";
tag_summary   = "Multiple vulnerabilities have been found in memcached, a high-performance
memory object caching system. The Common Vulnerabilities and Exposures
project identifies the following issues:

CVE-2011-4971 
Stefan Bucur reported that memcached could be caused to crash by
sending a specially crafted packet.

CVE-2013-7239 
It was reported that SASL authentication could be bypassed due to a
flaw related to the management of the SASL authentication state. With
a specially crafted request, a remote attacker may be able to
authenticate with invalid SASL credentials.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702832");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2011-4971", "CVE-2013-0179", "CVE-2013-7239");
    script_name("Debian Security Advisory DSA 2832-1 (memcached - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-01-01 00:00:00 +0100 (Wed, 01 Jan 2014)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2832.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
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

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"memcached", ver:"1.4.5-1+deb6u1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"memcached", ver:"1.4.13-0.2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
