###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1344_1.nasl 10387 2018-07-04 05:21:03Z cfischer $
#
# SuSE Update for curl openSUSE-SU-2018:1344-1 (curl)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851750");
  script_version("$Revision: 10387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 07:21:03 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-05-19 05:43:10 +0200 (Sat, 19 May 2018)");
  script_cve_id("CVE-2018-1000301");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for curl openSUSE-SU-2018:1344-1 (curl)");
  script_tag(name:"summary", value:"Check the version of curl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"
  This update for curl fixes several issues:

  Security issues fixed:

  - CVE-2018-1000301: Fixed a RTSP bad headers buffer over-read could crash
  the curl client (bsc#1092098)

  Non security issues fixed:

  - If the DEFAULT_SUSE cipher list is not available use the HIGH cipher
  alias before failing. (bsc#1086825)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-471=1");
  script_tag(name:"affected", value:"curl on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:1344_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-05/msg00083.html");
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

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel-32bit", rpm:"libcurl-devel-32bit~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-debuginfo-32bit", rpm:"libcurl4-debuginfo-32bit~7.37.0~36.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
