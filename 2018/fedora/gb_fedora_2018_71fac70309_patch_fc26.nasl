###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_71fac70309_patch_fc26.nasl 9192 2018-03-23 14:54:27Z cfischer $
#
# Fedora Update for patch FEDORA-2018-71fac70309
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
  script_oid("1.3.6.1.4.1.25623.1.0.874252");
  script_version("$Revision: 9192 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-23 15:54:27 +0100 (Fri, 23 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-21 15:10:48 +0100 (Wed, 21 Mar 2018)");
  script_cve_id("CVE-2016-10713", "CVE-2018-6951", "CVE-2018-6952");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for patch FEDORA-2018-71fac70309");
  script_tag(name: "summary", value: "Check the version of patch");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The patch program applies diff files to 
originals.  The diff command is used to compare an original to a changed file.  
Diff lists the changes made to the file.  A person who has the original file can 
then use the patch command with the diff file to add the changes to their original 
file (patching the file).

Patch should be installed because it is a common way of upgrading
applications.
");
  script_tag(name: "affected", value: "patch on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-71fac70309");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PV2HWN7IBAMPLAIOQYVGLUXFKXKYFZFT");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.6~3.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
