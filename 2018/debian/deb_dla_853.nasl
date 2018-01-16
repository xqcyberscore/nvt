###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_853.nasl 8426 2018-01-15 12:35:36Z teissa $
#
# Auto-generated from advisory DLA 853-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890853");
  script_version("$Revision: 8426 $");
  script_cve_id("CVE-2017-2640");
  script_name("Debian Lts Announce DLA 853-1 ([SECURITY] [DLA 853-1] pidgin security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-15 13:35:36 +0100 (Mon, 15 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"pidgin on Debian Linux");
  script_tag(name:"insight", value:"Pidgin is a graphical, modular instant messaging client capable of using
multiple networks at once. Currently supported are:
AIM/ICQ, Yahoo!, MSN, IRC, Jabber/XMPP/Google Talk, Napster, Zephyr, Gadu-Gadu,
Bonjour, Groupwise, Sametime, SIMPLE, MySpaceIM, and MXit.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
2.10.10-1~deb7u3.

We recommend that you upgrade your pidgin packages.");
  script_tag(name:"summary",  value:"It was discovered that an invalid XML file can trigger an out-of-bound
memory access in Pidgin, a multi-protocol instant messaging client,
when it is sent by a malicious server. This might lead to a crash or,
in some extreme cases, to remote code execution in the client-side.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"finch", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.10.10-1~deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
