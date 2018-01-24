###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1252.nasl 8499 2018-01-23 11:46:32Z teissa $
#
# Auto-generated from advisory DLA 1252-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891252");
  script_version("$Revision: 8499 $");
  script_cve_id("CVE-2017-12635", "CVE-2017-12636");
  script_name("Debian Lts Announce DLA 1252-1 ([SECURITY] [DLA 1252-1] couchdb security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 12:46:32 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-22 00:00:00 +0100 (Mon, 22 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00026.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"couchdb on Debian Linux");
  script_tag(name:"insight", value:"Apache CouchDB is a distributed, fault-tolerant and schema-free
document-oriented database accessible via a RESTful HTTP/JSON API. Among other
features, it provides robust, incremental replication with bi-directional
conflict detection and resolution, and is queryable and indexable using a
table-oriented view engine with JavaScript acting as the default view
definition language.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.2.0-5+deb7u1.

We recommend that you upgrade your couchdb packages.");
  script_tag(name:"summary",  value:"CVE-2017-12635
Prevent non-admin users to give themselves admin privileges.

CVE-2017-12636
Blacklist some configuration options to prevent execution of
arbitrary shell commands as the CouchDB user");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"couchdb", ver:"1.2.0-5+deb7u1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
