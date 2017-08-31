###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_08ec8b6dc4_open-vm-tools_fc26.nasl 6906 2017-08-11 13:21:18Z cfischer $
#
# Fedora Update for open-vm-tools FEDORA-2017-08ec8b6dc4
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
  script_oid("1.3.6.1.4.1.25623.1.0.873161");
  script_version("$Revision: 6906 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-11 15:21:18 +0200 (Fri, 11 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:07 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2015-5191");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for open-vm-tools FEDORA-2017-08ec8b6dc4");
  script_tag(name: "summary", value: "Check the version of open-vm-tools");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The open-vm-tools project is an open source 
implementation of VMware Tools. It is a suite of open source virtualization 
utilities and drivers to improve the functionality, user experience and 
administration of VMware virtual machines. This package contains only the core 
user-space programs and libraries of open-vm-tools.");
  script_tag(name: "affected", value: "open-vm-tools on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-08ec8b6dc4");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3QIKOPGHT5CTPEKNYZDCSQ6O5CAOJHBO");
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

  if ((res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~10.1.5~5.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
