###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_815.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 815-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890815");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-0358");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 815-1] ntfs-3g security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-05 00:00:00 +0100 (Fri, 05 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00002.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"ntfs-3g on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1:2012.1.15AR.5-2.1+deb7u3.

We recommend that you upgrade your ntfs-3g packages.");
  script_tag(name:"summary", value:"Jann Horn of Google Project Zero discovered that NTFS-3G, a read-write
NTFS driver for FUSE, does not scrub the environment before executing
modprobe with elevated privileges. A local user can take advantage of
this flaw for local root privilege escalation.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2012.1.15AR.5-2.1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfs-3g-dbg", ver:"1:2012.1.15AR.5-2.1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2012.1.15AR.5-2.1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfsprogs", ver:"1:2012.1.15AR.5-2.1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}