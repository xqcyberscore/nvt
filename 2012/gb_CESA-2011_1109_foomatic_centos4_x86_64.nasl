###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for foomatic CESA-2011:1109 centos4 x86_64
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
tag_insight = "Foomatic is a comprehensive, spooler-independent database of printers,
  printer drivers, and driver descriptions. The package also includes
  spooler-independent command line interfaces to manipulate queues and to
  print files and manipulate print jobs. foomatic-rip is a print filter
  written in Perl.

  An input sanitization flaw was found in the foomatic-rip print filter. An
  attacker could submit a print job with the username, title, or job options
  set to appear as a command line option that caused the filter to use a
  specified PostScript printer description (PPD) file, rather than the
  administrator-set one. This could lead to arbitrary code execution with the
  privileges of the &quot;lp&quot; user. (CVE-2011-2697)
  
  All foomatic users should upgrade to this updated package, which contains
  a backported patch to resolve this issue.";

tag_affected = "foomatic on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-August/017666.html");
  script_id(881351);
  script_version("$Revision: 8249 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 07:29:56 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:34:30 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2697");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2011:1109");
  script_name("CentOS Update for foomatic CESA-2011:1109 centos4 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of foomatic");
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

  if ((res = isrpmvuln(pkg:"foomatic", rpm:"foomatic~3.0.2~3.2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
