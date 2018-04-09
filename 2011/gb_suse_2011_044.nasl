###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for acroread SUSE-SA:2011:044
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "remote code execution";
tag_affected = "acroread on openSUSE 11.3, openSUSE 11.4";
tag_insight = "acrobat reader was updated to version 9.4.6 to fix several security issues that
  could allow attackers to execute arbitrary code or to cause a denial of service
  via specially crafted PDF documents.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850173");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-05 12:16:18 +0530 (Mon, 05 Dec 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "SUSE-SA", value: "2011-044");
  script_cve_id("CVE-2011-1353", "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433",
                "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437",
                "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441",
                "CVE-2011-2442");
  script_name("SuSE Update for acroread SUSE-SA:2011:044");

  script_tag(name:"summary", value:"Check for the Version of acroread");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
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

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~9.4.6~0.5.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~9.4.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
