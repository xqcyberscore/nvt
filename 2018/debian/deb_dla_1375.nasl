###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1375.nasl 10224 2018-06-15 14:29:06Z cfischer $
#
# Auto-generated from advisory DSA 1375-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891375");
  script_version("$Revision: 10224 $");
  script_cve_id("CVE-2018-0494");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1375-1] wget security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 16:29:06 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-14 00:00:00 +0200 (Mon, 14 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00006.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7\.[0-9]+");
  script_tag(name:"affected", value:"wget on Debian Linux");
  script_tag(name:"insight", value:"Wget is a network utility to retrieve files from the web
using HTTP(S) and FTP, the two most widely used internet
protocols. It works non-interactively, so it will work in
the background, after having logged off. The program supports
recursive retrieval of web-authoring pages as well as FTP
sites -- you can use Wget to make mirrors of archives and
home pages or to travel the web like a WWW robot.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.13.4-3+deb7u6.

We recommend that you upgrade your wget packages.");
  script_tag(name:"summary",  value:"Harry Sintonen have discovered a cookie injection vulnerability in
wget caused by insufficient input validation, enabling an external
attacker to inject arbitrary cookie values cookie jar file, adding new
or replacing existing cookie values.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"wget", ver:"1.13.4-3+deb7u6", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
