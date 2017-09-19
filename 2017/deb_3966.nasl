###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3966.nasl 7156 2017-09-18 05:28:25Z cfischer $
#
# Auto-generated from advisory DSA 3966-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703966");
  script_version("$Revision: 7156 $");
  script_cve_id("CVE-2015-9096", "CVE-2016-7798", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-14064");
  script_name("Debian Security Advisory DSA 3966-1 (ruby2.3 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 07:28:25 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-05 00:00:00 +0200 (Tue, 05 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3966.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"ruby2.3 on Debian Linux");
  script_tag(name:"insight", value:"Ruby is the interpreted scripting language for quick and easy
object-oriented programming. It has many features to process text
files and to do system management tasks (as in perl). It is simple,
straight-forward, and extensible.");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.3.3-1+deb9u1. This update also hardens RubyGems against
malicious terminal escape sequences (CVE-2017-0899 
).

We recommend that you upgrade your ruby2.3 packages.");
  script_tag(name:"summary",  value:"Multiple vulnerabilities were discovered in the interpreter for the Ruby
language:

CVE-2015-9096 
SMTP command injection in Net::SMTP.

CVE-2016-7798 
Incorrect handling of initialization vector in the GCM mode in the
OpenSSL extension.

CVE-2017-0900 
Denial of service in the RubyGems client.

CVE-2017-0901 
Potential file overwrite in the RubyGems client.

CVE-2017-0902 
DNS hijacking in the RubyGems client.

CVE-2017-14064 
Heap memory disclosure in the JSON library.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.3-dev", ver:"2.3.3-1+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.3-doc", ver:"2.3.3-1+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby2.3-tcltk", ver:"2.3.3-1+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
