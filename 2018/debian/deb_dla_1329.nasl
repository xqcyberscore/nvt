###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1329.nasl 10219 2018-06-15 12:00:55Z cfischer $
#
# Auto-generated from advisory DSA 1329-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891329");
  script_version("$Revision: 10219 $");
  script_cve_id("CVE-2018-1000127");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1329-1] memcached security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 14:00:55 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-04-02 00:00:00 +0200 (Mon, 02 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00031.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7\.[0-9]+");
  script_tag(name:"affected", value:"memcached on Debian Linux");
  script_tag(name:"insight", value:"Danga Interactive developed memcached to enhance the speed of LiveJournal.com,
a site which was already doing 20 million+ dynamic page views per day for 1
million users with a bunch of webservers and a bunch of database servers.
memcached dropped the database load to almost nothing, yielding faster page
load times for users, better resource utilization, and faster access to the
databases on a memcache miss.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.4.13-0.2+deb7u4.

We recommend that you upgrade your memcached packages.");
  script_tag(name:"summary",  value:"memcached version prior to 1.4.37 contains an Integer Overflow
vulnerability that can result in data corruption and deadlocks. This
attack is exploitable via network connectivity to the memcached
service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"memcached", ver:"1.4.13-0.2+deb7u4", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
