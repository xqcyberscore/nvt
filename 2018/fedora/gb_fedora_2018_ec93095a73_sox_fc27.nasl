###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_ec93095a73_sox_fc27.nasl 8858 2018-02-19 06:07:22Z cfischer $
#
# Fedora Update for sox FEDORA-2018-ec93095a73
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
  script_oid("1.3.6.1.4.1.25623.1.0.874120");
  script_version("$Revision: 8858 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-19 07:07:22 +0100 (Mon, 19 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 08:50:10 +0100 (Thu, 15 Feb 2018)");
  script_cve_id("CVE-2017-15372", "CVE-2017-15642");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for sox FEDORA-2018-ec93095a73");
  script_tag(name: "summary", value: "Check the version of sox");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "SoX (Sound eXchange) is a sound file format 
converter. SoX can convert between many different digitized sound formats and 
perform simple sound manipulation functions, including sound effects.
");
  script_tag(name: "affected", value: "sox on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-ec93095a73");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UH2SQ3KUA2QMA4QBGGATZPOG2AGLW7X7");
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

  if ((res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.2.0~16.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
