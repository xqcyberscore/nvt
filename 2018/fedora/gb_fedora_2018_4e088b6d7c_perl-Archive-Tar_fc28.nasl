###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_4e088b6d7c_perl-Archive-Tar_fc28.nasl 10645 2018-07-27 05:27:50Z cfischer $
#
# Fedora Update for perl-Archive-Tar FEDORA-2018-4e088b6d7c
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
  script_oid("1.3.6.1.4.1.25623.1.0.874696");
  script_version("$Revision: 10645 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 07:27:50 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 06:13:04 +0200 (Tue, 19 Jun 2018)");
  script_cve_id("CVE-2018-12015");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for perl-Archive-Tar FEDORA-2018-4e088b6d7c");
  script_tag(name:"summary", value:"Check the version of perl-Archive-Tar");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Archive::Tar provides an object oriented mechanism for handling tar
files.  It provides class methods for quick and easy files handling
while also allowing for the creation of tar file objects for custom
manipulation.  If you have the IO::Zlib module installed, Archive::Tar
will also support compressed or gzipped tar files.
");
  script_tag(name:"affected", value:"perl-Archive-Tar on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-4e088b6d7c");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BMHBMP53V6YZNF4A7B2HN6PD7NOFQHN6");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~2.28~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}