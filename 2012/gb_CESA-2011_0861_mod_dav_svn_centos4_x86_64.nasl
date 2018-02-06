###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mod_dav_svn CESA-2011:0861 centos4 x86_64
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
tag_insight = "Subversion (SVN) is a concurrent version control system which enables one
  or more users to collaborate in developing and maintaining a hierarchy of
  files and directories while keeping a history of all changes. The
  mod_dav_svn module is used with the Apache HTTP Server to allow access to
  Subversion repositories via HTTP.

  A NULL pointer dereference flaw was found in the way the mod_dav_svn module
  processed requests submitted against the URL of a baselined resource. A
  malicious, remote user could use this flaw to cause the httpd process
  serving the request to crash. (CVE-2011-1752)
  
  Red Hat would like to thank the Apache Subversion project for reporting
  this issue. Upstream acknowledges Joe Schaefer of the Apache Software
  Foundation as the original reporter.
  
  All Subversion users should upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  updated packages, you must restart the httpd daemon, if you are using
  mod_dav_svn, for the update to take effect.";

tag_affected = "mod_dav_svn on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-August/017676.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881275");
  script_version("$Revision: 8671 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:15:14 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1752");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2011:0861");
  script_name("CentOS Update for mod_dav_svn CESA-2011:0861 centos4 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of mod_dav_svn");
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


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.1.4~4.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.1.4~4.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.1.4~4.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.1.4~4.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
