###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1021.nasl 8699 2018-02-07 08:01:50Z asteins $
#
# Auto-generated from advisory DLA 1021-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891021");
  script_version("$Revision: 8699 $");
  script_cve_id("CVE-2017-9735");
  script_name("Debian Lts Announce DLA 1021-1 ([SECURITY] [DLA 1021-1] jetty8 security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-02-07 09:01:50 +0100 (Wed, 07 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-05 00:00:00 +0100 (Mon, 05 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00013.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"jetty8 on Debian Linux");
  script_tag(name:"insight", value:"Jetty is an Open Source HTTP Servlet Server written in 100% Java.
It is designed to be light weight, high performance, embeddable,
extensible and flexible, thus making it an ideal platform for serving
dynamic HTTP requests from any Java application.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
8.1.3-4+deb7u1.

We recommend that you upgrade your jetty8 packages.");
  script_tag(name:"summary",  value:"It was discovered that Jetty8, a Java servlet engine and webserver, was
vulnerable to a timing attack which might reveal cryptographic
credentials such as passwords to a local user.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"jetty8", ver:"8.1.3-4+deb7u1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libjetty8-extra-java", ver:"8.1.3-4+deb7u1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libjetty8-java", ver:"8.1.3-4+deb7u1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libjetty8-java-doc", ver:"8.1.3-4+deb7u1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
