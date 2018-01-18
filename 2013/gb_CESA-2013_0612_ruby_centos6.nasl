###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ruby CESA-2013:0612 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Ruby is an extensible, interpreted, object-oriented, scripting language. It
  has features to process text files and to do system management tasks.

  It was discovered that Ruby's REXML library did not properly restrict XML
  entity expansion. An attacker could use this flaw to cause a denial of
  service by tricking a Ruby application using REXML to read text nodes from
  specially-crafted XML content, which will result in REXML consuming large
  amounts of system memory. (CVE-2013-1821)
  
  It was found that the RHSA-2011:0910 update did not correctly fix the
  CVE-2011-1005 issue, a flaw in the method for translating an exception
  message into a string in the Exception class. A remote attacker could use
  this flaw to bypass safe level 4 restrictions, allowing untrusted (tainted)
  code to modify arbitrary, trusted (untainted) strings, which safe level 4
  restrictions would otherwise prevent. (CVE-2012-4481)
  
  The CVE-2012-4481 issue was discovered by Vit Ondruch of Red Hat.
  
  All users of Ruby are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";


tag_affected = "ruby on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-March/019633.html");
  script_id(881652);
  script_version("$Revision: 8456 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 07:58:40 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-03-12 10:00:15 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-4481", "CVE-2013-1821", "CVE-2011-1005");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2013:0612");
  script_name("CentOS Update for ruby CESA-2013:0612 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-static", rpm:"ruby-static~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.7.352~10.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
