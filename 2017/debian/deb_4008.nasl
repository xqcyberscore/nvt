###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4008.nasl 7615 2017-11-02 06:00:25Z teissa $
#
# Auto-generated from advisory DSA 4008-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704008");
  script_version("$Revision: 7615 $");
  script_cve_id("CVE-2017-13089", "CVE-2017-13090");
  script_name("Debian Security Advisory DSA 4008-1 (wget - security update)");
  script_tag(name:"last_modification", value:"$Date: 2017-11-02 07:00:25 +0100 (Thu, 02 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-28 00:00:00 +0200 (Sat, 28 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4008.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"wget on Debian Linux");
  script_tag(name:"insight", value:"Wget is a network utility to retrieve files from the web
using HTTP(S) and FTP, the two most widely used internet
protocols. It works non-interactively, so it will work in
the background, after having logged off. The program supports
recursive retrieval of web-authoring pages as well as FTP
sites -- you can use Wget to make mirrors of archives and
home pages or to travel the web like a WWW robot.");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.16-1+deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 1.18-5+deb9u1.

We recommend that you upgrade your wget packages.");
  script_tag(name:"summary",  value:"Antti Levomaeki, Christian Jalio, Joonas Pihlaja and Juhani Eronen
discovered two buffer overflows in the HTTP protocol handler of the Wget
download tool, which could result in the execution of arbitrary code
when connecting to a malicious HTTP server.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"wget", ver:"1.18-5+deb9u1", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wget", ver:"1.16-1+deb8u4", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
