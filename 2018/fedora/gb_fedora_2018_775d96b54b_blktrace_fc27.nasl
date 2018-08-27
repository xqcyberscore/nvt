###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_775d96b54b_blktrace_fc27.nasl 11128 2018-08-27 04:23:53Z ckuersteiner $
#
# Fedora Update for blktrace FEDORA-2018-775d96b54b
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874975");
  script_version("$Revision: 11128 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-27 06:23:53 +0200 (Mon, 27 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-20 11:18:33 +0200 (Mon, 20 Aug 2018)");
  script_cve_id("CVE-2018-10689");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for blktrace FEDORA-2018-775d96b54b");
  script_tag(name:"summary", value:"Check the version of blktrace");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"blktrace is a block layer IO tracing mechanism
which provides detailed information about request queue operations to user space.
This package includes both blktrace, a utility which gathers event traces from the
kernel  and blkparse, a utility which formats trace data collected by blktrace.

You should install the blktrace package if you need to gather detailed
information about IO patterns.
");
  script_tag(name:"affected", value:"blktrace on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-775d96b54b");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7AU76VLZEBM2B3D4IMLLLI4GY63MLHNN");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"blktrace", rpm:"blktrace~1.2.0~6.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
