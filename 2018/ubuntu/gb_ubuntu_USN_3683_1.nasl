###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3683_1.nasl 10215 2018-06-15 10:24:04Z cfischer $
#
# Ubuntu Update for bind9 USN-3683-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843560");
  script_version("$Revision: 10215 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 12:24:04 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-14 05:49:45 +0200 (Thu, 14 Jun 2018)");
  script_cve_id("CVE-2018-5738");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for bind9 USN-3683-1");
  script_tag(name:"summary", value:"Check the version of bind9");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"Andrew Skalski discovered that Bind could
incorrectly enable recursion when the 'allow-recursion' setting wasn't specified.
This issue could improperly permit recursion to all clients, contrary to
expectations.");
  script_tag(name:"affected", value:"bind9 on Ubuntu 18.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3683-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-3683-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.3+dfsg-1ubuntu1.1", rls:"UBUNTU18.04 LTS", remove_arch:TRUE )) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
