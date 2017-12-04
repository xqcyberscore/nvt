###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_fb1ae91f46_git-annex_fc27.nasl 7920 2017-11-28 07:49:35Z asteins $
#
# Fedora Update for git-annex FEDORA-2017-fb1ae91f46
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873796");
  script_version("$Revision: 7920 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-28 08:49:35 +0100 (Tue, 28 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:16:02 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-12976");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for git-annex FEDORA-2017-fb1ae91f46");
  script_tag(name: "summary", value: "Check the version of git-annex");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Git-annex allows managing files with git, 
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
  script_tag(name: "affected", value: "git-annex on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-fb1ae91f46");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4YF2RK56ULOFNXOTGTAUZ42LDGST6LLX");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"git-annex", rpm:"git-annex~6.20170925~3.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
