###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3937.nasl 9965 2018-05-25 14:06:08Z cfischer $
#
# Auto-generated from advisory DSA 3937-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703937");
  script_version("$Revision: 9965 $");
  script_cve_id("CVE-2017-2824", "CVE-2017-2825");
  script_name("Debian Security Advisory DSA 3937-1 (zabbix - security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-05-25 16:06:08 +0200 (Fri, 25 May 2018) $");
  script_tag(name:"creation_date", value:"2017-08-12 00:00:00 +0200 (Sat, 12 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3937.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"zabbix on Debian Linux");
  script_tag(name:"insight", value:"Zabbix is a server/client network monitoring system with many features.");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1:2.2.7+dfsg-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed
prior to the initial release.

We recommend that you upgrade your zabbix packages.");
  script_tag(name:"summary",  value:"Lilith Wyatt discovered two vulnerabilities in the Zabbix network
monitoring system which may result in execution of arbitrary code or
database writes by malicious proxies.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:2.2.7+dfsg-2+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
