###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_79841c871e_nodejs_fc27.nasl 10423 2018-07-05 13:03:28Z santu $
#
# Fedora Update for nodejs FEDORA-2018-79841c871e
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
  script_oid("1.3.6.1.4.1.25623.1.0.874759");
  script_version("$Revision: 10423 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 15:03:28 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-03 06:02:04 +0200 (Tue, 03 Jul 2018)");
  script_cve_id("CVE-2018-7162", "CVE-2018-7161", "CVE-2018-7167");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nodejs FEDORA-2018-79841c871e");
  script_tag(name:"summary", value:"Check the version of nodejs");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Node.js is a platform built on Chrome&#39 s 
JavaScript runtime for easily building fast, scalable network applications.
Node.js uses an event-driven, non-blocking I/O model that makes it lightweight and 
efficient, perfect for data-intensive real-time applications that run across 
distributed devices.
");
  script_tag(name:"affected", value:"nodejs on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-79841c871e");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/E4NZYDJWDA7IWLZ76VO4GKQ4ZJMVXWLL");
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

  if ((res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~8.11.3~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
