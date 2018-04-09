###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for php-phar MDVSA-2011:004 (php-phar)
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
tag_insight = "A vulnerability has been found and corrected in php-phar:

  Multiple format string vulnerabilities in the phar extension in PHP
  5.3 before 5.3.2 allow context-dependent attackers to obtain sensitive
  information (memory contents) and possibly execute arbitrary code
  via a crafted phar:// URI that is not properly handled by the (1)
  phar_stream_flush, (2) phar_wrapper_unlink, (3) phar_parse_url, or
  (4) phar_wrapper_open_url functions in ext/phar/stream.c; and the (5)
  phar_wrapper_open_dir function in ext/phar/dirstream.c, which triggers
  errors in the php_stream_wrapper_log_error function (CVE-2010-2094).
  
  The updated packages have been upgraded to the latest version (2.0.0)
  and patched to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "php-phar on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-01/msg00005.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831305");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 16:07:43 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2011:004");
  script_cve_id("CVE-2010-2094");
  script_name("Mandriva Update for php-phar MDVSA-2011:004 (php-phar)");

  script_tag(name:"summary", value:"Check for the Version of php-phar");
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

  if ((res = isrpmvuln(pkg:"php-phar", rpm:"php-phar~2.0.0~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
