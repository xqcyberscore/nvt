###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_e22c8eb218_git-annex_fc28.nasl 10502 2018-07-13 13:19:46Z santu $
#
# Fedora Update for git-annex FEDORA-2018-e22c8eb218
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
  script_oid("1.3.6.1.4.1.25623.1.0.874793");
  script_version("$Revision: 10502 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-13 15:19:46 +0200 (Fri, 13 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-12 06:10:50 +0200 (Thu, 12 Jul 2018)");
  script_cve_id("CVE-2018-10857", "CVE-2018-10859");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for git-annex FEDORA-2018-e22c8eb218");
  script_tag(name:"summary", value:"Check the version of git-annex");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is 
present on the target host.");
  script_tag(name:"insight", value:"Git-annex allows managing files with git, 
without checking the file contents into git. While that may seem paradoxical, 
it is useful when dealing with files larger than git can currently easily handle, 
whether due to limitations in memory, time, or disk space.

It can store large files in many places, from local hard drives, to a large
number of cloud storage services, including S3, WebDAV, and rsync, with a dozen
cloud storage providers usable via plugins. Files can be stored encrypted with
gpg, so that the cloud storage provider cannot see your data.
git-annex keeps track of where each file is stored, so it knows how many copies
are available, and has many facilities to ensure your data is preserved.

git-annex can also be used to keep a folder in sync between computers, noticing
when files are changed, and automatically committing them to git and
transferring them to other computers. The git-annex webapp makes it easy to set
up and use git-annex this way.
");
  script_tag(name:"affected", value:"git-annex on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-e22c8eb218");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N27SN5NCGQYHJ6OQMHGUO7OBWRDYDIXM");
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

  if ((res = isrpmvuln(pkg:"git-annex", rpm:"git-annex~6.20180626~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
