# OpenVAS Vulnerability Test
# $Id: deb_2783.nasl 7585 2017-10-26 15:03:01Z cfischer $
# Auto-generated from advisory DSA 2783-1 using nvtgen 1.0
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

tag_affected  = "librack-ruby on Debian Linux";
tag_insight   = "Rack provides a minimal, modular and adaptable interface for
developing web applications in Ruby. By wrapping HTTP requests and
responses in the simplest way possible, it unifies and distills the
API for web servers, web frameworks, and software in between (the
so-called middleware) into a single method call.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.1.0-4+squeeze1.

The stable, testing and unstable distributions do not contain the
librack-ruby package. They have already been addressed in version
1.4.1-2.1 of the ruby-rack package.

We recommend that you upgrade your librack-ruby packages.";
tag_summary   = "Several vulnerabilities were discovered in Rack, a modular Ruby
webserver interface. The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:

CVE-2011-5036 
Rack computes hash values for form parameters without restricting
the ability to trigger hash collisions predictably, which allows
remote attackers to cause a denial of service (CPU consumption)
by sending many crafted parameters.

CVE-2013-0183 
A remote attacker could cause a denial of service (memory
consumption and out-of-memory error) via a long string in a
Multipart HTTP packet.

CVE-2013-0184 
A vulnerability in Rack::Auth::AbstractRequest allows remote
attackers to cause a denial of service via unknown vectors.

CVE-2013-0263 
Rack::Session::Cookie allows remote attackers to guess the
session cookie, gain privileges, and execute arbitrary code via a
timing attack involving an HMAC comparison function that does not
run in constant time.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_id(892783);
    script_version("$Revision: 7585 $");
    script_cve_id("CVE-2011-5036", "CVE-2013-0183", "CVE-2013-0184", "CVE-2013-0263");
    script_name("Debian Security Advisory DSA 2783-1 (librack-ruby - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
    script_tag(name: "creation_date", value:"2013-10-21 00:00:00 +0200 (Mon, 21 Oct 2013)");
    script_tag(name: "cvss_base", value:"5.1");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2783.html");


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
if ((res = isdpkgvuln(pkg:"librack-ruby", ver:"1.1.0-4+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"librack-ruby1.8", ver:"1.1.0-4+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"librack-ruby1.9.1", ver:"1.1.0-4+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
