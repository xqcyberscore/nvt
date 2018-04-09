###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for augeas CESA-2014:0044 centos6 
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
  script_oid("1.3.6.1.4.1.25623.1.0.881862");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 13:00:11 +0530 (Tue, 21 Jan 2014)");
  script_cve_id("CVE-2013-6412");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for augeas CESA-2014:0044 centos6 ");

  tag_insight = "Augeas is a utility for editing configuration. Augeas parses configuration
files in their native formats and transforms them into a tree.
Configuration changes are made by manipulating this tree and saving it back
into native configuration files. Augeas also uses 'lenses' as basic
building blocks for establishing the mapping from files into the Augeas
tree and back.

A flaw was found in the way Augeas handled certain umask settings when
creating new configuration files. This flaw could result in configuration
files being created as world writable, allowing unprivileged local users to
modify their content. (CVE-2013-6412)

This issue was discovered by the Red Hat Security Response Team.

All augeas users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. All running applications
using augeas must be restarted for the update to take effect.
";

  tag_affected = "augeas on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2014:0044");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2014-January/020110.html");
  script_tag(name:"summary", value:"Check for the Version of augeas");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"augeas", rpm:"augeas~1.0.0~5.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"augeas-devel", rpm:"augeas-devel~1.0.0~5.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"augeas-libs", rpm:"augeas-libs~1.0.0~5.el6_5.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
