###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_51ff8fe326_poppler_fc26.nasl 7760 2017-11-15 05:34:04Z teissa $
#
# Fedora Update for poppler FEDORA-2017-51ff8fe326
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
  script_oid("1.3.6.1.4.1.25623.1.0.873577");
  script_version("$Revision: 7760 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-15 06:34:04 +0100 (Wed, 15 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-08 10:31:21 +0100 (Wed, 08 Nov 2017)");
  script_cve_id("CVE-2017-14926", "CVE-2017-14927", "CVE-2017-14928", "CVE-2017-14617", 
                "CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14519", "CVE-2017-14929");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for poppler FEDORA-2017-51ff8fe326");
  script_tag(name: "summary", value: "Check the version of poppler");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "poppler is a PDF rendering library.
");
  script_tag(name: "affected", value: "poppler on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-51ff8fe326");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FY2H4JEZCCGU7CIQ62ZV2MWXCRNEPJ4W");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.52.0~9.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
