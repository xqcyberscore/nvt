###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1435.nasl 10566 2018-07-23 07:41:10Z cfischer $
#
# Auto-generated from advisory DLA 1435-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891435");
  script_version("$Revision: 10566 $");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1435-1] dnsmasq regression update)");
  script_tag(name:"last_modification", value:"$Date: 2018-07-23 09:41:10 +0200 (Mon, 23 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-23 00:00:00 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00027.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"dnsmasq on Debian Linux");
  script_tag(name:"insight", value:"Dnsmasq is a lightweight, easy to configure, DNS forwarder and DHCP
server. It is designed to provide DNS and optionally, DHCP, to a
small network. It can serve the names of local machines which are
not in the global DNS. The DHCP server integrates with the DNS
server and allows machines with DHCP-allocated addresses
to appear in the DNS with names configured either in each host or
in a central configuration file. Dnsmasq supports static and dynamic
DHCP leases and BOOTP/TFTP for network booting of diskless machines.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
2.72-3+deb8u3.

We recommend that you upgrade your dnsmasq packages.");
  script_tag(name:"summary",  value:"The dns-root-data update to 2017072601~deb8u2 broke dnsmasq's
init script, making dnsmasq no longer start when dns-root-data
was installed.

This update fixes dnsmasq's parsing of dns-root-data.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"dnsmasq", ver:"2.72-3+deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.72-3+deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.72-3+deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
