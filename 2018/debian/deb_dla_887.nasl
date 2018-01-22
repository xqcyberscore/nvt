###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_887.nasl 8460 2018-01-18 11:25:52Z teissa $
#
# Auto-generated from advisory DLA 887-1 using nvtgen 1.0
# Script version:1.0
# #
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
  script_oid("1.3.6.1.4.1.25623.1.0.890887");
  script_version("$Revision: 8460 $");
  
  script_name("Debian Lts Announce DLA 887-1 ([SECURITY] [DLA 887-1] libdatetime-timezone-perl new upstream version)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 12:25:52 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00006.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"libdatetime-timezone-perl on Debian Linux");
  script_tag(name:"insight", value:"DateTime::TimeZone is a Perl module framework providing an interface to the
Olson time zone database. It exposes the database as a set of modules, one
for each time zone defined, allowing for various optimizations in doing time
zone calculations.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1:1.58-1+2017b.

We recommend that you upgrade your libdatetime-timezone-perl packages.");
  script_tag(name:"summary",  value:"This update includes the changes in tzdata 2017b for the
Perl bindings. For the list of changes, see DLA-886-1.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libdatetime-timezone-perl", ver:"1:1.58-1+2017b", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
