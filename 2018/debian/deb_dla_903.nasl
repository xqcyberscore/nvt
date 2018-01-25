###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_903.nasl 8515 2018-01-24 11:16:13Z teissa $
#
# Auto-generated from advisory DLA 903-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890903");
  script_version("$Revision: 8515 $");
  
  script_name("Debian Lts Announce DLA 903-1 ([SECURITY] [DLA 903-1] hunspell-en-us update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 12:16:13 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00022.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"hunspell-en-us on Debian Linux");
  script_tag(name:"insight", value:"This is the English_american dictionary for use with the hunspell spellchecker");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this problem has been fixed in version
20070829-6+deb7u1.

We recommend that you upgrade your hunspell-en-us packages.");
  script_tag(name:"summary",  value:"The dictionary provided by this package had an unnecessary unversioned
conflict against the thunderbird package which recently got reintroduced
into Wheezy.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"hunspell-en-us", ver:"20070829-6+deb7u1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
