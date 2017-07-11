###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for exim openSUSE-SU-2017:1625-1 (exim)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851569");
  script_version("$Revision: 6420 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-23 15:10:46 +0200 (Fri, 23 Jun 2017) $");
  script_tag(name:"creation_date", value:"2017-06-20 17:22:14 +0200 (Tue, 20 Jun 2017)");
  script_cve_id("CVE-2017-1000369");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for exim openSUSE-SU-2017:1625-1 (exim)");
  script_tag(name: "summary", value: "Check the version of exim");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for exim fixes the following issues:

  - CVE-2017-1000369: Fixed a memory leak in exim commandline handling,
  which could be used to exhaust memory and make 'stack crash' attacks
  likely. (boo#1044692)");
  script_tag(name: "affected", value: "exim on openSUSE Leap 42.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2017:1625_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2017-06/msg00020.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.86.2~10.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-debuginfo", rpm:"exim-debuginfo~4.86.2~10.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-debugsource", rpm:"exim-debugsource~4.86.2~10.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eximon", rpm:"eximon~4.86.2~10.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eximon-debuginfo", rpm:"eximon-debuginfo~4.86.2~10.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eximstats-html", rpm:"eximstats-html~4.86.2~10.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
