###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for t1lib CESA-2012:0062 centos6 
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
tag_insight = "The t1lib library allows you to rasterize bitmaps from PostScript Type 1
  fonts.

  Two heap-based buffer overflow flaws were found in the way t1lib processed
  Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened
  by an application linked against t1lib, it could cause the application to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2010-2642, CVE-2011-0433)
  
  An invalid pointer dereference flaw was found in t1lib. A specially-crafted
  font file could, when opened, cause an application linked against t1lib to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2011-0764)
  
  A use-after-free flaw was found in t1lib. A specially-crafted font file
  could, when opened, cause an application linked against t1lib to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2011-1553)
  
  An off-by-one flaw was found in t1lib. A specially-crafted font file could,
  when opened, cause an application linked against t1lib to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the application. (CVE-2011-1554)
  
  An out-of-bounds memory read flaw was found in t1lib. A specially-crafted
  font file could, when opened, cause an application linked against t1lib to
  crash. (CVE-2011-1552)
  
  Red Hat would like to thank the Evince development team for reporting
  CVE-2010-2642. Upstream acknowledges Jon Larimer of IBM X-Force as the
  original reporter of CVE-2010-2642.
  
  All users of t1lib are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. All applications linked
  against t1lib must be restarted for this update to take effect.";

tag_affected = "t1lib on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-January/018395.html");
  script_id(881199);
  script_version("$Revision: 8257 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 07:29:46 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:40:59 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552",
                "CVE-2011-1553", "CVE-2011-1554");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2012:0062");
  script_name("CentOS Update for t1lib CESA-2012:0062 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of t1lib");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"t1lib", rpm:"t1lib~5.1.2~6.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-apps", rpm:"t1lib-apps~5.1.2~6.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-devel", rpm:"t1lib-devel~5.1.2~6.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-static", rpm:"t1lib-static~5.1.2~6.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
