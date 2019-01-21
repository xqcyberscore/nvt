###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_dbcb80405c_nbdkit_fc28.nasl 13173 2019-01-21 06:39:39Z santu $
#
# Fedora Update for nbdkit FEDORA-2018-dbcb80405c
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.875408");
  script_version("$Revision: 13173 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 07:39:39 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-15 04:03:20 +0100 (Tue, 15 Jan 2019)");
  script_name("Fedora Update for nbdkit FEDORA-2018-dbcb80405c");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-dbcb80405c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4CC257C54YT73RUK5RM4DCOJLQ756K52");

  script_tag(name:"summary", value:"The remote host is missing an update for
  the 'nbdkit' package(s) announced via the FEDORA-2018-dbcb80405c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"NBD is a protocol for accessing block devices
  (hard disks and disk-like things) over the network.

&#39 nbdkit&#39  is a toolkit for creating NBD servers.

The key features are:

* Multithreaded NBD server written in C with good performance.

* Well-documented, simple plugin API with a stable ABI guarantee.
  Allows you to export 'unconventional' block devices easily.

* Liberal license (BSD) allows nbdkit to be linked to proprietary
  libraries or included in proprietary code.

You probably want to install one of more plugins (nbdkit-plugin-*).

To develop plugins, install the nbdkit-devel package and start by
reading the nbdkit(1) and nbdkit-plugin(3) manual pages.
");

  script_tag(name:"affected", value:"nbdkit on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"nbdkit", rpm:"nbdkit~1.4.4~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
