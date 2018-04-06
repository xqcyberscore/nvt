###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php-pecl-apc RHSA-2012:0811-04
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

tag_affected = "php-pecl-apc on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-June/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870762");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:25:59 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2010-3294");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "RHSA", value: "2012:0811-04");
  script_name("RedHat Update for php-pecl-apc RHSA-2012:0811-04");

  script_tag(name: "summary" , value: "Check for the Version of php-pecl-apc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"php-pecl-apc", rpm:"php-pecl-apc~3.1.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pecl-apc-debuginfo", rpm:"php-pecl-apc-debuginfo~3.1.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
