###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0019_1.nasl 8313 2018-01-08 07:02:11Z teissa $
#
# SuSE Update for krb5-appl openSUSE-SU-2012:0019-1 (krb5-appl)
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
tag_insight = "This update of krb5 applications fixes two security issues.

  CVE-2011-4862: A remote code execution in the kerberized
  telnet daemon was fixed. (This only affects the ktelnetd
  from the krb5-appl RPM, not the regular telnetd supplied by
  SUSE.)

  CVE-2011-1526 / MITKRB5-SA-2011-005: Fixed krb5 ftpd
  unauthorized file access problems.";

tag_affected = "krb5-appl on openSUSE 11.4, openSUSE 11.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850296);
  script_version("$Revision: 8313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 08:02:11 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 23:39:09 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-4862", "CVE-2011-1526");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "openSUSE-SU", value: "2012:0019_1");
  script_name("SuSE Update for krb5-appl openSUSE-SU-2012:0019-1 (krb5-appl)");

  script_tag(name: "summary" , value: "Check for the Version of krb5-appl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

  if ((res = isrpmvuln(pkg:"krb5-appl-clients", rpm:"krb5-appl-clients~1.0~7.12.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-appl-servers", rpm:"krb5-appl-servers~1.0~7.12.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"krb5-appl-clients", rpm:"krb5-appl-clients~1.0~4.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-appl-servers", rpm:"krb5-appl-servers~1.0~4.5.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
