###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_903354c26c_osc-source_validator_fc26.nasl 9226 2018-03-28 03:48:50Z ckuersteiner $
#
# Fedora Update for osc-source_validator FEDORA-2018-903354c26c
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
  script_oid("1.3.6.1.4.1.25623.1.0.874021");
  script_version("$Revision: 9226 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-28 05:48:50 +0200 (Wed, 28 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-01-17 07:38:37 +0100 (Wed, 17 Jan 2018)");
  script_cve_id("CVE-2017-9274");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for osc-source_validator FEDORA-2018-903354c26c");
  script_tag(name: "summary", value: "Check the version of osc-source_validator");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This is a source service for openSUSE 
Build Service.

This service runs all checks as required by openSUSE:Factory project. This can be 
used to guarantee that all checks succeed also on the service side. This plugin 
can be used via project wide defined services.
");
  script_tag(name: "affected", value: "osc-source_validator on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-903354c26c");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZUMUHP7L2QKENEH4YOEPZSCTKS2442ET");
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

  if ((res = isrpmvuln(pkg:"osc-source_validator", rpm:"osc-source_validator~0.10~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
