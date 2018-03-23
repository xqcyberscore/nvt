###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_14f5c6cdac_qpid-cpp_fc27.nasl 9180 2018-03-22 15:38:54Z cfischer $
#
# Fedora Update for qpid-cpp FEDORA-2017-14f5c6cdac
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
  script_oid("1.3.6.1.4.1.25623.1.0.874011");
  script_version("$Revision: 9180 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-22 16:38:54 +0100 (Thu, 22 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-01-14 07:32:48 +0100 (Sun, 14 Jan 2018)");
  script_cve_id("CVE-2015-0203");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qpid-cpp FEDORA-2017-14f5c6cdac");
  script_tag(name: "summary", value: "Check the version of qpid-cpp");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Run-time libraries for AMQP client 
applications developed using Qpid C++. Clients exchange messages with an 
AMQP message broker using the AMQP protocol.
");
  script_tag(name: "affected", value: "qpid-cpp on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-14f5c6cdac");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SFEMQMBVRYGFSV2SRLZBLXEEUV6TBT5J");
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

  if ((res = isrpmvuln(pkg:"qpid-cpp", rpm:"qpid-cpp~1.37.0~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
