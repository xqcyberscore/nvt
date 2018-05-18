###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1137_1.nasl 9903 2018-05-18 09:08:09Z asteins $
#
# SuSE Update for patch openSUSE-SU-2018:1137-1 (patch)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851739");
  script_version("$Revision: 9903 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-18 11:08:09 +0200 (Fri, 18 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-04 05:36:45 +0200 (Fri, 04 May 2018)");
  script_cve_id("CVE-2016-10713", "CVE-2018-1000156", "CVE-2018-6951");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for patch openSUSE-SU-2018:1137-1 (patch)");
  script_tag(name:"summary", value:"Check the version of patch");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"
  This update for patch fixes the following issues:

  Security issues fixed:

  - CVE-2018-1000156: Malicious patch files cause ed to execute arbitrary
  commands (bsc#1088420).
  - CVE-2018-6951: Fixed NULL pointer dereference in the intuit_diff_type
  function in pch.c (bsc#1080918).
  - CVE-2016-10713: Fixed out-of-bounds access within pch_write_line() in
  pch.c (bsc#1080918).

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-416=1");
  script_tag(name:"affected", value:"patch on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:1137_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-05/msg00004.html");
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

  if ((res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.5~9.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"patch-debuginfo", rpm:"patch-debuginfo~2.7.5~9.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"patch-debugsource", rpm:"patch-debugsource~2.7.5~9.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
