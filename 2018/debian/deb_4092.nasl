###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4092.nasl 8493 2018-01-23 06:43:13Z ckuersteiner $
#
# Auto-generated from advisory DSA 4092-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.704092");
  script_version("$Revision: 8493 $");
  script_cve_id("CVE-2017-1000501");
  script_name("Debian Security Advisory DSA 4092-1 (awstats - security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:43:13 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-19 00:00:00 +0100 (Fri, 19 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4092.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"awstats on Debian Linux");
  script_tag(name:"insight", value:"Advanced Web Statistics (AWStats) is a powerful web server logfile
analyzer written in perl that shows you all your web statistics including
visits, unique visitors, pages, hits, rush hours, search engines, keywords
used to find your site, robots, broken links and more. Gives more detailed
information and better graphical charts than webalizer, and is easier to use.
Works with several web server log format as a CGI and/or from command line.
Supports more than 30 languages.");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 7.2+dfsg-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 7.6+dfsg-1+deb9u1.

We recommend that you upgrade your awstats packages.

For the detailed security status of awstats please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/awstats");
  script_tag(name:"summary",  value:"The cPanel Security Team discovered that awstats, a log file analyzer,
was vulnerable to path traversal attacks. A remote unauthenticated
attacker could leverage that to perform arbitrary code execution.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"awstats", ver:"7.6+dfsg-1+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"awstats", ver:"7.2+dfsg-1+deb8u1", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
