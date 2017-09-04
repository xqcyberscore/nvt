###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_ee93493bea_community-mysql_fc26.nasl 7026 2017-08-31 06:13:04Z asteins $
#
# Fedora Update for community-mysql FEDORA-2017-ee93493bea
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
  script_oid("1.3.6.1.4.1.25623.1.0.873246");
  script_version("$Revision: 7026 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 08:13:04 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-12 07:50:18 +0200 (Sat, 12 Aug 2017)");
  script_cve_id("CVE-2017-3633", "CVE-2017-3634", "CVE-2017-3635", "CVE-2017-3641", 
                "CVE-2017-3647", "CVE-2017-3648", "CVE-2017-3649", "CVE-2017-3651", 
                "CVE-2017-3652", "CVE-2017-3653", "CVE-2017-3636");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for community-mysql FEDORA-2017-ee93493bea");
  script_tag(name: "summary", value: "Check the version of community-mysql");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "MySQL is a multi-user, multi-threaded 
SQL database server. MySQL is a client/server implementation consisting of 
a server daemon (mysqld) and many different client programs and libraries. 
The base package contains the standard MySQL client programs and generic MySQL files.");
  script_tag(name: "affected", value: "community-mysql on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-ee93493bea");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OIWXNME53JCA4FZOJLPPOSEJKM4KQYEB");
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

  if ((res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~5.7.19~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
