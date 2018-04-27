###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1038_1.nasl 9630 2018-04-26 12:38:23Z santu $
#
# SuSE Update for cfitsio openSUSE-SU-2018:1038-1 (cfitsio)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851733");
  script_version("$Revision: 9630 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 14:38:23 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-21 09:00:41 +0200 (Sat, 21 Apr 2018)");
  script_cve_id("CVE-2018-1000166");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for cfitsio openSUSE-SU-2018:1038-1 (cfitsio)");
  script_tag(name: "summary", value: "Check the version of cfitsio");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for cfitsio fixes the following issues:

  Security issues fixed:

  - CVE-2018-1000166: Unsafe use of sprintf() can allow a remote
  unauthenticated attacker to execute arbitrary code (boo#1088590)

  This update to version 3.430 also contains a number of upstream bug fixes.

  The following tracked packaging changes are included:

  - boo#1082318: package licence text as license, not as documentation


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-383=1");
  script_tag(name: "affected", value: "cfitsio on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:1038_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-04/msg00062.html");
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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"cfitsio", rpm:"cfitsio~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cfitsio-debuginfo", rpm:"cfitsio-debuginfo~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cfitsio-debugsource", rpm:"cfitsio-debugsource~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cfitsio-devel", rpm:"cfitsio-devel~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cfitsio-devel-doc", rpm:"cfitsio-devel-doc~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcfitsio5", rpm:"libcfitsio5~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcfitsio5-debuginfo", rpm:"libcfitsio5-debuginfo~3.430~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
