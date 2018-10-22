###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_4f0089c995_yum-utils_fc28.nasl 11994 2018-10-19 16:13:16Z cfischer $
#
# Fedora Update for yum-utils FEDORA-2018-4f0089c995
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
  script_oid("1.3.6.1.4.1.25623.1.0.875113");
  script_version("$Revision: 11994 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 18:13:16 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-09-28 13:35:42 +0200 (Fri, 28 Sep 2018)");
  script_cve_id("CVE-2018-10897");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for yum-utils FEDORA-2018-4f0089c995");
  script_tag(name:"summary", value:"Check the version of yum-utils");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"yum-utils is a collection of utilities and
  examples for the yum package manager. It includes utilities by different authors
  that make yum easier and more powerful to use. These tools include: debuginfo-install,
  find-repos-of-install, needs-restarting, package-cleanup, repoclosure, repodiff,
  repo-graph, repomanage, repoquery, repo-rss, reposync, repotrack, show-installed,
  show-changed-rco, verifytree, yumdownloader, yum-builddep, yum-complete-transaction,
  yum-config-manager, yum-debug-dump, yum-debug-restore and yum-groups-manager.
");
  script_tag(name:"affected", value:"yum-utils on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-4f0089c995");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HIJSDH2IJCF5PQXVAMDP4ZDMYSDSHRPT");
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

  if ((res = isrpmvuln(pkg:"yum-utils", rpm:"yum-utils~1.1.31~515.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
