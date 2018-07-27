###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2010_1.nasl 10645 2018-07-27 05:27:50Z cfischer $
#
# SuSE Update for perl openSUSE-SU-2018:2010-1 (perl)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851818");
  script_version("$Revision: 10645 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 07:27:50 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-20 05:54:42 +0200 (Fri, 20 Jul 2018)");
  script_cve_id("CVE-2018-12015");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for perl openSUSE-SU-2018:2010-1 (perl)");
  script_tag(name:"summary", value:"Check the version of perl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"
  This update for perl fixes the following issues:

  This security issue was fixed:

  - CVE-2018-12015: The Archive::Tar module allowed remote attackers to
  bypass a directory-traversal protection mechanism and overwrite
  arbitrary files (bsc#1096718)

  This non-security issue was fixed:

  - fix debugger crash in tab completion with Term::ReadLine::Gnu
  [bsc#1068565]

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-750=1");
  script_tag(name:"affected", value:"perl on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:2010_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00023.html");
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

  if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-base-debuginfo", rpm:"perl-base-debuginfo~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-debugsource", rpm:"perl-debugsource~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-32bit", rpm:"perl-32bit~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-base-32bit", rpm:"perl-base-32bit~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-base-debuginfo-32bit", rpm:"perl-base-debuginfo-32bit~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-debuginfo-32bit", rpm:"perl-debuginfo-32bit~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.18.2~15.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}