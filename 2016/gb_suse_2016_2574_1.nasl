###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for ghostscript-library openSUSE-SU-2016:2574-1 (ghostscript-library)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851413");
  script_version("$Revision: 4367 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-27 14:59:58 +0200 (Thu, 27 Oct 2016) $");
  script_tag(name:"creation_date", value:"2016-10-21 05:54:14 +0200 (Fri, 21 Oct 2016)");
  script_cve_id("CVE-2013-5653", "CVE-2016-7978", "CVE-2016-7979");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ghostscript-library openSUSE-SU-2016:2574-1 (ghostscript-library)");
  script_tag(name: "summary", value: "Check the version of ghostscript-library");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for ghostscript-library fixes the following issues:

  - Multiple security vulnerabilities have been discovered where
  ghostscript's '-dsafer' flag did not provide sufficient protection
  against unintended access to the file system. Thus, a machine that would
  process a specially crafted Postscript file would potentially leak
  sensitive information to an attacker. (CVE-2013-5653, bsc#1001951)

  - An incorrect reference count was found in .setdevice. This issue lead to
  a use-after-free scenario, which could have been exploited for
  denial-of-service or, possibly, arbitrary code execution attacks.
  (CVE-2016-7978, bsc#1001951)

  - Insufficient validation of the type of input in .initialize_dsc_parser
  used to allow remote code execution. (CVE-2016-7979, bsc#1001951)

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name: "affected", value: "ghostscript-library on openSUSE Leap 42.1");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2016:2574_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2016-10/msg00033.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_summary("Check for the Version of ghostscript-library");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:opensuse:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-mini", rpm:"ghostscript-mini~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-mini-debuginfo", rpm:"ghostscript-mini-debuginfo~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-mini-debugsource", rpm:"ghostscript-mini-debugsource~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-mini-devel", rpm:"ghostscript-mini-devel~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-x11-debuginfo", rpm:"ghostscript-x11-debuginfo~9.15~8.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
