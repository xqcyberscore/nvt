###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1249.nasl 8506 2018-01-24 03:45:11Z ckuersteiner $
#
# Auto-generated from advisory DLA 1249-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891249");
  script_version("$Revision: 8506 $");
  script_cve_id("CVE-2017-1000480");
  script_name("Debian Lts Announce DLA 1249-1 ([SECURITY] [DLA 1249-1] smarty3 security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 04:45:11 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-22 00:00:00 +0100 (Mon, 22 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00023.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"smarty3 on Debian Linux");
  script_tag(name:"insight", value:"Smarty is a template engine for PHP. More specifically, it
facilitates a manageable way to separate application logic and content
from its presentation.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this issue has been fixed in smarty3 version
3.1.10-2+deb7u2.

We recommend that you upgrade your smarty3 packages.");
  script_tag(name:"summary",  value:"It was discovered that there was a code-injection vulnerability in smarty3,
a PHP template engine.

A via specially-crafted filename in comments could result in arbitray code
execution. Thanks to Mike Gabriel for backporting the patch.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"smarty3", ver:"3.1.10-2+deb7u2", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
