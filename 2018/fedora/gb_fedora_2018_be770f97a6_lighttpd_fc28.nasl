###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_be770f97a6_lighttpd_fc28.nasl 11110 2018-08-25 05:03:07Z santu $
#
# Fedora Update for lighttpd FEDORA-2018-be770f97a6
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
  script_oid("1.3.6.1.4.1.25623.1.0.874983");
  script_version("$Revision: 11110 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-25 07:03:07 +0200 (Sat, 25 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-23 07:48:31 +0200 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for lighttpd FEDORA-2018-be770f97a6");
  script_tag(name:"summary", value:"Check the version of lighttpd");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"Secure, fast, compliant and very flexible
web-server which has been optimized for high-performance environments. It has a
very low memory footprint compared to other webservers and takes care of cpu-load.
Its advanced feature-set (FastCGI, CGI, Auth, Output-Compression, URL-Rewriting
and many more) make it the perfect webserver-software for every server that is
suffering load problems.
");
  script_tag(name:"affected", value:"lighttpd on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-be770f97a6");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PDOQELVRGJWNLEIWYDFTNM2UTWDC7ZKB");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.50~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
