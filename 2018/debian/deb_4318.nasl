###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4318.nasl 11912 2018-10-16 06:18:46Z cfischer $
#
# Auto-generated from advisory DSA 4318-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704318");
  script_version("$Revision: 11912 $");
  script_cve_id("CVE-2017-5934");
  script_name("Debian Security Advisory DSA 4318-1 (moin - security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 08:18:46 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-15 00:00:00 +0200 (Mon, 15 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4318.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9\.[0-9]+");
  script_tag(name:"affected", value:"moin on Debian Linux");
  script_tag(name:"insight", value:"A WikiWikiWeb is a collaborative hypertext environment, with an
emphasis on easy access to and modification of information. MoinMoin
is a Python WikiClone that allows you to easily set up your own wiki,
only requiring a Web server and a Python installation.");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 1.9.9-1+deb9u1.

We recommend that you upgrade your moin packages.

For the detailed security status of moin please refer to its security
tracker page at:
https://security-tracker.debian.org/tracker/moin");
  script_tag(name:"summary",  value:"Nitin Venkatesh discovered a cross-site scripting vulnerability in moin,
a Python clone of WikiWiki. A remote attacker can conduct cross-site
scripting attacks via the GUI editor's link dialogue. This only affects
installations which have set up fckeditor (not enabled by default).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.9.9-1+deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
