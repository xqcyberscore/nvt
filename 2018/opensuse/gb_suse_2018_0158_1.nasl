###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0158_1.nasl 8566 2018-01-29 10:57:43Z santu $
#
# SuSE Update for xmltooling openSUSE-SU-2018:0158-1 (xmltooling)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851684");
  script_version("$Revision: 8566 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-29 11:57:43 +0100 (Mon, 29 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-21 07:41:19 +0100 (Sun, 21 Jan 2018)");
  script_cve_id("CVE-2018-0486");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xmltooling openSUSE-SU-2018:0158-1 (xmltooling)");
  script_tag(name: "summary", value: "Check the version of xmltooling");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for xmltooling fixes the following issues:

  - CVE-2018-0486: Fixed a security bug when xmltooling mishandles digital
  signatures of user attribute data, which allows remote attackers to
  obtain sensitive information or conduct impersonation attacks via a
  crafted DTD (bsc#1075975)

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");
  script_tag(name: "affected", value: "xmltooling on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0158_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~1.5.6~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxmltooling6", rpm:"libxmltooling6~1.5.6~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxmltooling6-debuginfo", rpm:"libxmltooling6-debuginfo~1.5.6~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmltooling-debugsource", rpm:"xmltooling-debugsource~1.5.6~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~1.5.6~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~1.5.6~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxmltooling6", rpm:"libxmltooling6~1.5.6~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxmltooling6-debuginfo", rpm:"libxmltooling6-debuginfo~1.5.6~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmltooling-debugsource", rpm:"xmltooling-debugsource~1.5.6~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~1.5.6~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
