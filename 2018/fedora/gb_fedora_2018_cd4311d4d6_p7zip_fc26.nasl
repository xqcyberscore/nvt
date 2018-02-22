###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_cd4311d4d6_p7zip_fc26.nasl 8893 2018-02-21 06:36:27Z cfischer $
#
# Fedora Update for p7zip FEDORA-2018-cd4311d4d6
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
  script_oid("1.3.6.1.4.1.25623.1.0.874102");
  script_version("$Revision: 8893 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-21 07:36:27 +0100 (Wed, 21 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-07 08:08:44 +0100 (Wed, 07 Feb 2018)");
  script_cve_id("CVE-2017-17969");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for p7zip FEDORA-2018-cd4311d4d6");
  script_tag(name: "summary", value: "Check the version of p7zip");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "p7zip is a port of 7za.exe for Unix. 
7-Zip is a file archiver with a very high compression ratio. The original version 
can be found at 'http://www.7-zip.org/'.
");
  script_tag(name: "affected", value: "p7zip on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-cd4311d4d6");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OY277AYKTUMMV6YWUBYJR4OAPWP2BNGM");
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

  if ((res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~16.02~9.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
