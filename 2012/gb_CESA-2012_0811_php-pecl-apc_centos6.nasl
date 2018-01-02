###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for php-pecl-apc CESA-2012:0811 centos6 
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

tag_insight = "The php-pecl-apc packages contain APC (Alternative PHP Cache), the
  framework for caching and optimization of intermediate PHP code.

  A cross-site scripting (XSS) flaw was found in the &quot;apc.php&quot; script, which
  provides a detailed analysis of the internal workings of APC and is shipped
  as part of the APC extension documentation. A remote attacker could
  possibly use this flaw to conduct a cross-site scripting attack.
  (CVE-2010-3294)
  
  Note: The administrative script is not deployed upon package installation.
  It must manually be copied to the web root (the default is
  &quot;/var/www/html/&quot;, for example).
  
  In addition, the php-pecl-apc packages have been upgraded to upstream
  version 3.1.9, which provides a number of bug fixes and enhancements over
  the previous version. (BZ#662655)
  
  All users of php-pecl-apc are advised to upgrade to these updated packages,
  which fix these issues and add these enhancements. If the &quot;apc.php&quot; script
  was previously deployed in the web root, it must manually be re-deployed to
  replace the vulnerable version to resolve this issue.";

tag_affected = "php-pecl-apc on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-July/018713.html");
  script_id(881098);
  script_version("$Revision: 8253 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 07:29:51 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:08:01 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-3294");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "CESA", value: "2012:0811");
  script_name("CentOS Update for php-pecl-apc CESA-2012:0811 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of php-pecl-apc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"php-pecl-apc", rpm:"php-pecl-apc~3.1.9~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pecl-apc-devel", rpm:"php-pecl-apc-devel~3.1.9~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
