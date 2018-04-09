###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mod_dav_svn CESA-2013:0737 centos5
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
tag_insight = "Subversion (SVN) is a concurrent version control system which enables one
  or more users to collaborate in developing and maintaining a hierarchy of
  files and directories while keeping a history of all changes. The
  mod_dav_svn module is used with the Apache HTTP Server to allow access to
  Subversion repositories via HTTP.

  A NULL pointer dereference flaw was found in the way the mod_dav_svn module
  handled PROPFIND requests on activity URLs. A remote attacker could use
  this flaw to cause the httpd process serving the request to crash.
  (CVE-2013-1849)

  A flaw was found in the way the mod_dav_svn module handled large numbers
  of properties (such as those set with the &quot;svn propset&quot; command).
  A malicious, remote user could use this flaw to cause the httpd process
  serving the request to consume an excessive amount of system memory.
  (CVE-2013-1845)

  Two NULL pointer dereference flaws were found in the way the mod_dav_svn
  module handled LOCK requests on certain types of URLs. A malicious, remote
  user could use these flaws to cause the httpd process serving the request
  to crash. (CVE-2013-1846, CVE-2013-1847)

  Note: The CVE-2013-1849, CVE-2013-1846, and CVE-2013-1847 issues only
  caused a temporary denial of service, as the Apache HTTP Server started a
  new process to replace the crashed child process. When using prefork MPM,
  the crash only affected the attacker. When using worker (threaded) MPM, the
  connections of other users may have been interrupted.

  Red Hat would like to thank the Apache Subversion project for reporting
  these issues. Upstream acknowledges Alexander Klink as the original
  reporter of CVE-2013-1845; Ben Reser as the original reporter of
  CVE-2013-1846; and Philip Martin and Ben Reser as the original reporters of
  CVE-2013-1847.

  All subversion users should upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing the
  updated packages, you must restart the httpd daemon, if you are using
  mod_dav_svn, for the update to take effect.";


tag_affected = "mod_dav_svn on CentOS 5";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881710");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-15 10:13:06 +0530 (Mon, 15 Apr 2013)");
  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for mod_dav_svn CESA-2013:0737 centos5 ");

  script_xref(name: "CESA", value: "2013:0737");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-April/019687.html");
  script_tag(name:"summary", value:"Check for the Version of mod_dav_svn");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.6.11~11.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.6.11~11.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.6.11~11.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.6.11~11.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.6.11~11.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.6.11~11.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
