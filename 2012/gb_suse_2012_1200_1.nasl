###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1200_1.nasl 8313 2018-01-08 07:02:11Z teissa $
#
# SuSE Update for freeradius openSUSE-SU-2012:1200-1 (freeradius)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_affected = "freeradius on openSUSE 12.1, openSUSE 11.4";
tag_insight = "This update of freeradius fixes a stack overflow in TLS
  handling, which can be exploited by remote attackers able
  to access Radius to execute code.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850337);
  script_version("$Revision: 8313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 08:02:11 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:02:06 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-3547");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "openSUSE-SU", value: "2012:1200_1");
  script_name("SuSE Update for freeradius openSUSE-SU-2012:1200-1 (freeradius)");

  script_tag(name: "summary" , value: "Check for the Version of freeradius");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-devel", rpm:"freeradius-server-devel~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-dialupadmin", rpm:"freeradius-server-dialupadmin~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~2.1.10~8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"freeradius-server", rpm:"freeradius-server~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-debuginfo", rpm:"freeradius-server-debuginfo~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-debugsource", rpm:"freeradius-server-debugsource~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-devel", rpm:"freeradius-server-devel~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-dialupadmin", rpm:"freeradius-server-dialupadmin~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-doc", rpm:"freeradius-server-doc~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-libs", rpm:"freeradius-server-libs~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-libs-debuginfo", rpm:"freeradius-server-libs-debuginfo~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-utils", rpm:"freeradius-server-utils~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-server-utils-debuginfo", rpm:"freeradius-server-utils-debuginfo~2.1.12~4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}