###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_ef9e28d9e4_poco_fc27.nasl 8709 2018-02-08 06:30:35Z cfischer $
#
# Fedora Update for poco FEDORA-2018-ef9e28d9e4
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
  script_oid("1.3.6.1.4.1.25623.1.0.874058");
  script_version("$Revision: 8709 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 07:30:35 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-27 07:51:19 +0100 (Sat, 27 Jan 2018)");
  script_cve_id("CVE-2017-1000472");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for poco FEDORA-2018-ef9e28d9e4");
  script_tag(name: "summary", value: "Check the version of poco");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The POCO C++ Libraries (POCO stands for 
POrtable COmponents) are open source C++ class libraries that simplify and 
accelerate the development of network-centric, portable applications in C++. 
The POCO C++ Libraries are built strictly on standard ANSI/ISO C++, including 
the standard library.
");
  script_tag(name: "affected", value: "poco on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-ef9e28d9e4");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SVBK53QIF633ETBZE7L6H46QDQTDOIDE");
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

  if ((res = isrpmvuln(pkg:"poco", rpm:"poco~1.7.8p3~3.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
