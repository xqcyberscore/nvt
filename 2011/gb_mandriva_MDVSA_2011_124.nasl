###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for phpmyadmin MDVSA-2011:124 (phpmyadmin)
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
tag_insight = "Multiple vulnerabilities has been discovered and corrected in
  phpmyadmin:

  libraries/auth/swekey/swekey.auth.lib.php in the Swekey authentication
  feature in phpMyAdmin 3.x before 3.3.10.2 and 3.4.x before 3.4.3.1
  assigns values to arbitrary parameters referenced in the query string,
  which allows remote attackers to modify the SESSION superglobal array
  via a crafted request, related to a remote variable manipulation
  vulnerability. (CVE-2011-2505).
  
  setup/lib/ConfigGenerator.class.php in phpMyAdmin 3.x before 3.3.10.2
  and 3.4.x before 3.4.3.1 does not properly restrict the presence of
  comment closing delimiters, which allows remote attackers to conduct
  static code injection attacks by leveraging the ability to modify
  the SESSION superglobal array (CVE-2011-2506).
  
  libraries/server_synchronize.lib.php in the Synchronize implementation
  in phpMyAdmin 3.x before 3.3.10.2 and 3.4.x before 3.4.3.1 does not
  properly quote regular expressions, which allows remote authenticated
  users to inject a PCRE e (aka PREG_REPLACE_EVAL) modifier, and
  consequently execute arbitrary PHP code, by leveraging the ability
  to modify the SESSION superglobal array (CVE-2011-2507).
  
  Directory traversal vulnerability in libraries/display_tbl.lib.php
  in phpMyAdmin 3.x before 3.3.10.2 and 3.4.x before 3.4.3.1, when
  a certain MIME transformation feature is enabled, allows remote
  authenticated users to include and execute arbitrary local files
  via a .. (dot dot) in a GLOBALS[mime_map][-&amp;gt;name][transformation]
  parameter (CVE-2011-2508).
  
  Multiple cross-site scripting (XSS) vulnerabilities in the table Print
  view implementation in tbl_printview.php in phpMyAdmin before 3.3.10.3
  and 3.4.x before 3.4.3.2 allow remote authenticated users to inject
  arbitrary web script or HTML via a crafted table name (CVE-2011-2642).
  
  Directory traversal vulnerability in sql.php in phpMyAdmin 3.4.x before
  3.4.3.2, when configuration storage is enabled, allows remote attackers
  to include and execute arbitrary local files via directory traversal
  sequences in a MIME-type transformation parameter (CVE-2011-2643).
  
  Multiple directory traversal vulnerabilities in the relational
  schema implementation in phpMyAdmin 3.4.x before 3.4.3.2 allow remote
  authenticated users to include and execute arbitrary local files via
  directory traversal sequences in an export type field, related to
  (1) libraries/schema/User_Schema.class.php and (2) schema_export.php
  (CVE-2011-2718).
  
  libraries/auth/swekey/swekey.auth.lib ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "phpmyadmin on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-08/msg00006.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831441");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2011:124");
  script_cve_id("CVE-2011-2505", "CVE-2011-2506", "CVE-2011-2507", "CVE-2011-2508", "CVE-2011-2642", "CVE-2011-2643", "CVE-2011-2718", "CVE-2011-2719");
  script_name("Mandriva Update for phpmyadmin MDVSA-2011:124 (phpmyadmin)");

  script_tag(name:"summary", value:"Check for the Version of phpmyadmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~3.4.3.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
