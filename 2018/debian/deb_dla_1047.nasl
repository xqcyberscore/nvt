###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1047.nasl 8749 2018-02-09 15:39:38Z teissa $
#
# Auto-generated from advisory DLA 1047-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891047");
  script_version("$Revision: 8749 $");
  script_cve_id("CVE-2017-11610");
  script_name("Debian Lts Announce DLA 1047-1 ([SECURITY] [DLA 1047-1] supervisor security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-02-09 16:39:38 +0100 (Fri, 09 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00042.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"supervisor on Debian Linux");
  script_tag(name:"insight", value:"Supervisor is a system for controlling and maintaining process state,
similar to what init does, but not intended as an init replacement.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.0a8-1.1+deb7u2.

We recommend that you upgrade your supervisor packages.");
  script_tag(name:"summary",  value:"vulnerability has been found in supervisor, a system for controlling
process state, where an authenticated client can send a malicious
XML-RPC request to supervisord that will run arbitrary shell commands
on the server. The commands will be run as the same user as supervisord.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"supervisor", ver:"3.0a8-1.1+deb7u2", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
