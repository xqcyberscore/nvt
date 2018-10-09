###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4312.nasl 11791 2018-10-09 08:56:15Z cfischer $
#
# Auto-generated from advisory DSA 4312-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704312");
  script_version("$Revision: 11791 $");
  script_cve_id("CVE-2018-16738", "CVE-2018-16758");
  script_name("Debian Security Advisory DSA 4312-1 (tinc - security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 10:56:15 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-08 00:00:00 +0200 (Mon, 08 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4312.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9\.[0-9]+");
  script_tag(name:"affected", value:"tinc on Debian Linux");
  script_tag(name:"insight", value:"tinc is a daemon with which you can create a virtual private network
(VPN). One daemon can handle multiple connections, so you can
create an entire (moderately sized) VPN with only one daemon per
participating computer.");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 1.0.31-1+deb9u1.

We recommend that you upgrade your tinc packages.

For the detailed security status of tinc please refer to its security
tracker page at:
https://security-tracker.debian.org/tracker/tinc");
  script_tag(name:"summary",  value:"Several vulnerabilities were discovered in tinc, a Virtual Private
Network (VPN) daemon. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2018-16738 
Michael Yonli discovered a flaw in the implementation of the
authentication protocol that could allow a remote attacker to
establish an authenticated, one-way connection with another node.

CVE-2018-16758 
Michael Yonli discovered that a man-in-the-middle that has
intercepted a TCP connection might be able to disable encryption of
UDP packets sent by a node.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"tinc", ver:"1.0.31-1+deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
