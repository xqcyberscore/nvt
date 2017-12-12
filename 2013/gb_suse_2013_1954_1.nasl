###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_1954_1.nasl 8045 2017-12-08 08:39:37Z santu $
#
# SuSE Update for Fixes openSUSE-SU-2013:1954-1 (Fixes)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(850562);
  script_version("$Revision: 8045 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:39:37 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-12-30 13:02:29 +0530 (Mon, 30 Dec 2013)");
  script_cve_id("CVE-2013-3709");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for Fixes openSUSE-SU-2013:1954-1 (Fixes)");

  tag_insight = "
  Fixed CVE-2013-3709: make the secret token file
  (secret_token.rb) readable only for the webyast user to
  avoid forging the session cookie (bnc#851116) (reported by
  joernchen of Phenoelit)";

  tag_affected = "Fixes on openSUSE 12.2";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "openSUSE-SU", value: "2013:1954_1");
  script_summary("Check for the Version of Fixes");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"webyast-base", rpm:"webyast-base~0.3.19.1~1.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webyast-base-branding-default", rpm:"webyast-base-branding-default~0.3.19.1~1.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webyast-base-testsuite", rpm:"webyast-base-testsuite~0.3.19.1~1.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}