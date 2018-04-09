###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for phpmyadmin MDVSA-2011:000 (phpmyadmin)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Multiple vulnerabilities has been found and corrected in phpmyadmin:

  error.php in PhpMyAdmin 3.3.8.1 and earlier allows remote attackers
  to conduct cross-site scripting (XSS) attacks via a crafted BBcode
  tag containing @ characters, as demonstrated using [a@url@page]
  (CVE-2010-4480).
  
  phpMyAdmin before 3.4.0-beta1 allows remote attackers to bypass
  authentication and obtain sensitive information via a direct request
  to phpinfo.php, which calls the phpinfo function (CVE-2010-4481).
  
  This upgrade provides the latest phpmyadmin version for MES5 (3.3.9)
  and patches the version for CS4 to address these vulnerabilities.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "phpmyadmin on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-01/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831299");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-11 16:07:49 +0100 (Tue, 11 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "MDVSA", value: "2011:000");
  script_cve_id("CVE-2010-4480", "CVE-2010-4481");
  script_name("Mandriva Update for phpmyadmin MDVSA-2011:000 (phpmyadmin)");

  script_tag(name:"summary", value:"Check for the Version of phpmyadmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~3.3.9~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
