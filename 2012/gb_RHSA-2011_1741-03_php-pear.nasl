###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php-pear RHSA-2011:1741-03
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
tag_insight = "The php-pear package contains the PHP Extension and Application Repository
  (PEAR), a framework and distribution system for reusable PHP components.

  It was found that the &quot;pear&quot; command created temporary files in an insecure
  way when installing packages. A malicious, local user could use this flaw
  to conduct a symbolic link attack, allowing them to overwrite the contents
  of arbitrary files accessible to the victim running the &quot;pear install&quot;
  command. (CVE-2011-1072)

  This update also fixes the following bugs:

  * The php-pear package has been upgraded to version 1.9.4, which provides a
  number of bug fixes over the previous version. (BZ#651897)

  * Prior to this update, php-pear created a cache in the
  &quot;/var/cache/php-pear/&quot; directory when attempting to list all packages. As a
  consequence, php-pear failed to create or update the cache file as a
  regular user without sufficient file permissions and could not list all
  packages. With this update, php-pear no longer fails if writing to the
  cache directory is not permitted. Now, all packages are listed as expected.
  (BZ#747361)

  All users of php-pear are advised to upgrade to this updated package, which
  corrects these issues.";

tag_affected = "php-pear on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-December/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870625");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:35:17 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1072");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "RHSA", value: "2011:1741-03");
  script_name("RedHat Update for php-pear RHSA-2011:1741-03");

  script_tag(name: "summary" , value: "Check for the Version of php-pear");
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

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~1.9.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
