###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1481_1.nasl 8253 2017-12-28 06:29:51Z teissa $
#
# SuSE Update for opera openSUSE-SU-2012:1481-1 (opera)
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
tag_insight = "This Opera 12.10 security update fixes following security
  issues:
  -an issue that could cause Opera not to correctly check for
  certificate revocation;
  -an issue where CORS requests could incorrectly retrieve
  contents of cross origin pages;
  -an issue where data URIs could be used to facilitate
  Cross-Site Scripting;
  -a high severity issue, as reported by Gareth Heyes;
  details will be disclosed at a later date
  -an issue where specially crafted SVG images could allow
  execution of arbitrary code;
  -a moderate severity issue, as reported by the Google
  Security Group; details will be disclosed at a later date

  Full changelog available at:
  http://www.opera.com/docs/changelogs/unix/1210";

tag_affected = "opera on openSUSE 12.1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850361);
  script_version("$Revision: 8253 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 07:29:51 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:18 +0530 (Thu, 13 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "openSUSE-SU", value: "2012:1481_1");
  script_name("SuSE Update for opera openSUSE-SU-2012:1481-1 (opera)");

  script_tag(name: "summary" , value: "Check for the Version of opera");
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

if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~12.10~26.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opera-gtk", rpm:"opera-gtk~12.10~26.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opera-kde4", rpm:"opera-kde4~12.10~26.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
