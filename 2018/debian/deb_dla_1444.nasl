###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1444.nasl 10664 2018-07-27 13:57:41Z cfischer $
#
# Auto-generated from advisory DLA 1444-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891444");
  script_version("$Revision: 10664 $");
  script_cve_id("CVE-2018-11319");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1444-1] vim-syntastic security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 15:57:41 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-27 00:00:00 +0200 (Fri, 27 Jul 2018)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00036.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"vim-syntastic on Debian Linux");
  script_tag(name:"insight", value:"Syntastic is a syntax checking plugin that runs files through external syntax
checkers and displays any resulting errors to the user. This can be done on
demand, or automatically as files are saved. If syntax errors are detected, the
user is notified and is happy because they didn't have to compile their code or
execute their script to find them.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
3.5.0-1+deb8u1.

We recommend that you upgrade your vim-syntastic packages.");
  script_tag(name:"summary",  value:"CVE-2018-11319
The improper handling of search for configuration files might be
exploited for arbitrary code execution via a malicious gcc plugin.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"vim-syntastic", ver:"3.5.0-1+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
