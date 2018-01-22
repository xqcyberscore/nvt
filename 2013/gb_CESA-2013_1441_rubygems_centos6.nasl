###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rubygems CESA-2013:1441 centos6 
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

if(description)
{
  script_id(881804);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-10-21 10:01:10 +0530 (Mon, 21 Oct 2013)");
  script_cve_id("CVE-2012-2125", "CVE-2012-2126", "CVE-2013-4287");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for rubygems CESA-2013:1441 centos6 ");

  tag_insight = "RubyGems is the Ruby standard for publishing and managing third-party
libraries.

It was found that RubyGems did not verify SSL connections. This could lead
to man-in-the-middle attacks. (CVE-2012-2126)

It was found that, when using RubyGems, the connection could be redirected
from HTTPS to HTTP. This could lead to a user believing they are installing
a gem via HTTPS, when the connection may have been silently downgraded to
HTTP. (CVE-2012-2125)

It was discovered that the rubygems API validated version strings using an
unsafe regular expression. An application making use of this API to process
a version string from an untrusted source could be vulnerable to a denial
of service attack through CPU exhaustion. (CVE-2013-4287)

Red Hat would like to thank Rubygems upstream for reporting CVE-2013-4287.
Upstream acknowledges Damir Sharipov as the original reporter.

All rubygems users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.
";

  tag_affected = "rubygems on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1441");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-October/019977.html");
  script_tag(name: "summary" , value: "Check for the Version of rubygems");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~1.3.7~4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}