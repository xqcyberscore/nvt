###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_3054_1.nasl 8091 2017-12-13 06:22:57Z teissa $
#
# SuSE Update for otrs openSUSE-SU-2017:3054-1 (otrs)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851650");
  script_version("$Revision: 8091 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-13 07:22:57 +0100 (Wed, 13 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-24 07:29:54 +0100 (Fri, 24 Nov 2017)");
  script_cve_id("CVE-2017-15864", "CVE-2017-16664");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for otrs openSUSE-SU-2017:3054-1 (otrs)");
  script_tag(name: "summary", value: "Check the version of otrs");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for otrs fixes the following security issues:

  - CVE-2017-15864: Remote authenticated attackers could have caused otrs to
  disclose configuration information, including database credentials
  (boo#1068677, OSA-2017-06)
  - CVE-2017-16664: Remote authenticated attackers could have caused the
  execution of shell commands with the permission of the web server user
  (boo#1069391, OSA-2017-07)");
  script_tag(name: "affected", value: "otrs on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2017:3054_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.3.20~5.11.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"otrs-doc", rpm:"otrs-doc~3.3.20~5.11.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"otrs-itsm", rpm:"otrs-itsm~3.3.14~5.11.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.3.20~14.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"otrs-doc", rpm:"otrs-doc~3.3.20~14.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"otrs-itsm", rpm:"otrs-itsm~3.3.14~14.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
