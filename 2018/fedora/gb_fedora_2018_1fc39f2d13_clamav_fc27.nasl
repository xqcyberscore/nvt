###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_1fc39f2d13_clamav_fc27.nasl 12056 2018-10-24 12:04:11Z santu $
#
# Fedora Update for clamav FEDORA-2018-1fc39f2d13
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
  script_oid("1.3.6.1.4.1.25623.1.0.875200");
  script_version("$Revision: 12056 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:04:11 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-17 06:38:06 +0200 (Wed, 17 Oct 2018)");
  script_cve_id("CVE-2018-15378", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682",
                "CVE-2018-14679", "CVE-2012-6706", "CVE-2017-6419", "CVE-2017-11423",
                "CVE-2018-1000085", "CVE-2018-0202", "CVE-2017-12374", "CVE-2017-12375",
                "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379",
                "CVE-2017-12380", "CVE-2017-6420", "CVE-2017-6418");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for clamav FEDORA-2018-1fc39f2d13");
  script_tag(name:"summary", value:"Check the version of clamav");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
 on the target host.");
  script_tag(name:"insight", value:"Clam AntiVirus is an anti-virus toolkit for
  UNIX. The main purpose of this software is the integration with mail servers
  (attachment scanning). The package provides a flexible and scalable multi-threaded
  daemon, a command line scanner, and a tool for automatic updating via Internet.
  The programs are based on a shared library distributed with the Clam AntiVirus
  package, which you can use with your own software. The virus database is based
  on the virus database from OpenAntiVirus, but contains additional signatures
  (including signatures for popular polymorphic viruses, too) and is KEPT UP TO DATE.");
  script_tag(name:"affected", value:"clamav on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-1fc39f2d13");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P4OAK7NHFUENOT57B7HZBDLSLSAOFVEZ");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.2~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
