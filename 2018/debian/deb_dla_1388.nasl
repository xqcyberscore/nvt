###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1388.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1388-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891388");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-11358", "CVE-2018-11362", "CVE-2018-9258", "CVE-2018-9260", "CVE-2018-9261",
                "CVE-2018-9263", "CVE-2018-9268", "CVE-2018-9269", "CVE-2018-9270");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1388-1] wireshark security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-05-29 00:00:00 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00019.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"wireshark on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.12.1+g01b65bf-4+deb8u6~deb7u11.

We recommend that you upgrade your wireshark packages.");
  script_tag(name:"summary", value:"Several issues that could result in a crash within different dissectors have been fixed. Other issues are related to memory leaks or heap-based buffer overflows.


All issue could be caused by special crafted and malformed packets.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
# nb: libwireshark2, libwiretap2 and libwsutil2 having a lower version 1.8.2-5wheezy18, keep this in mind when overwriting this LSC
if((res = isdpkgvuln(pkg:"libwireshark-data", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tshark", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-doc", ver:"1.12.1+g01b65bf-4+deb8u6~deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}