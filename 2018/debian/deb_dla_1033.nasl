###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1033.nasl 10219 2018-06-15 12:00:55Z cfischer $
#
# Auto-generated from advisory DLA 1033-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891033");
  script_version("$Revision: 10219 $");
  script_cve_id("CVE-2016-8705", "CVE-2017-9951");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1033-1] memcached security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 14:00:55 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00025.html");

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
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this issue has been fixed in memcached version
1.4.13-0.2+deb7u3.

We recommend that you upgrade your memcached packages.");
  script_tag(name:"summary",  value:"It was discovered that there was a remote denial-of-service (DoS) vulnerability
in memcached, a high-performance memory object caching system.

The try_read_command function allowed remote attackers to cause a DoS via a
request to add/set a key that makes a comparison between a signed and unsigned
integer which triggered a heap-based buffer over-read.

This vulnerability existed due to an incomplete upstream fix for CVE-2016-8705.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"memcached", ver:"1.4.13-0.2+deb7u3", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
