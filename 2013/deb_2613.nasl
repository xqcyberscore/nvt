# OpenVAS Vulnerability Test
# $Id: deb_2613.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2613-1 using nvtgen 1.0
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

tag_affected  = "rails on Debian Linux";
tag_insight   = "Rails is a full-stack, open-source web framework in Ruby for writing
real-world applications.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze6.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.14-6 of the ruby-activesupport-2.3 package.

The 3.2 version of rails as found in Debian wheezy and sid is not
affected by the problem.

We recommend that you upgrade your rails packages.";
tag_summary   = "Lawrence Pit discovered that Ruby on Rails, a web development framework,
is vulnerable to a flaw in the parsing of JSON to YAML. Using a specially
crafted payload attackers can trick the backend into decoding a subset of
YAML.

The vulnerability has been addressed by removing the YAML backend and
adding the OkJson backend.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892613");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-0333");
    script_name("Debian Security Advisory DSA 2613-1 (rails - insufficient input validation)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-01-29 00:00:00 +0100 (Tue, 29 Jan 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2613.html");


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
if ((res = isdpkgvuln(pkg:"libactionmailer-ruby", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactionmailer-ruby1.8", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactionpack-ruby", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactionpack-ruby1.8", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactiverecord-ruby", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactiverecord-ruby1.8", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactiverecord-ruby1.9.1", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactiveresource-ruby", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactiveresource-ruby1.8", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivesupport-ruby", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivesupport-ruby1.8", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libactivesupport-ruby1.9.1", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rails", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rails-doc", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rails-ruby1.8", ver:"2.3.5-1.2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
