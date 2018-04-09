###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2014:0310 centos5 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881901");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-03-20 09:43:07 +0530 (Thu, 20 Mar 2014)");
  script_cve_id("CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508",
                "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512",
                "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for firefox CESA-2014:0310 centos5 ");

  tag_insight = "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-1493, CVE-2014-1510, CVE-2014-1511, CVE-2014-1512,
CVE-2014-1513, CVE-2014-1514)

Several information disclosure flaws were found in the way Firefox
processed malformed web content. An attacker could use these flaws to gain
access to sensitive information such as cross-domain content or protected
memory addresses or, potentially, cause Firefox to crash. (CVE-2014-1497,
CVE-2014-1508, CVE-2014-1505)

A memory corruption flaw was found in the way Firefox rendered certain PDF
files. An attacker able to trick a user into installing a malicious
extension could use this flaw to crash Firefox or, potentially, execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2014-1509)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij,
Jesse Ruderman, Dan Gohman, Christoph Diehl, Atte Kettunen, Tyson Smith,
Jesse Schwartzentruber, John Thomson, Robert O'Callahan, Mariusz Mlynski,
Juri Aedla, George Hotz, and the security research firm VUPEN as the
original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 24.4.0 ESR. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 24.4.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect.
";

  tag_affected = "firefox on CentOS 5";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2014:0310");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2014-March/020217.html");
  script_tag(name:"summary", value:"Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~24.4.0~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
