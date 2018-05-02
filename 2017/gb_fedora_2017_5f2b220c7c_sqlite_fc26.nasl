###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_5f2b220c7c_sqlite_fc26.nasl 9681 2018-05-02 02:36:53Z ckuersteiner $
#
# Fedora Update for sqlite FEDORA-2017-5f2b220c7c
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
  script_oid("1.3.6.1.4.1.25623.1.0.873262");
  script_version("$Revision: 9681 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-02 04:36:53 +0200 (Wed, 02 May 2018) $");
  script_tag(name:"creation_date", value:"2017-08-14 07:44:20 +0200 (Mon, 14 Aug 2017)");
  script_cve_id("CVE-2017-7000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for sqlite FEDORA-2017-5f2b220c7c");
  script_tag(name: "summary", value: "Check the version of sqlite");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "SQLite is a C library that implements an 
SQL database engine. A large subset of SQL92 is supported. A complete database 
is stored in a single disk file. The API is designed for convenience and ease 
of use. Applications that link against SQLite can enjoy the power and
flexibility of an SQL database without the administrative hassles of
supporting a separate database server.  Version 2 and version 3 binaries
are named to permit each to be installed on a single host
");
  script_tag(name: "affected", value: "sqlite on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-5f2b220c7c");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6TBSWZVTNL543ZOO5JEDDBOOTMYUQWKH");
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

  if ((res = isrpmvuln(pkg:"sqlite", rpm:"sqlite~3.20.0~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
