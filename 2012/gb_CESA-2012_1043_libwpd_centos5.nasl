###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libwpd CESA-2012:1043 centos5 
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
tag_insight = "libwpd is a library for reading and converting Corel WordPerfect Office
  documents.

  A buffer overflow flaw was found in the way libwpd processed certain
  Corel WordPerfect Office documents (.wpd files). An attacker could provide
  a specially-crafted .wpd file that, when opened in an application linked
  against libwpd, such as OpenOffice.org, would cause the application to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2012-2149)
  
  All libwpd users are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running applications
  that are linked against libwpd must be restarted for this update to take
  effect.";

tag_affected = "libwpd on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-June/018700.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881106");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:09:14 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2149");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2012:1043");
  script_name("CentOS Update for libwpd CESA-2012:1043 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of libwpd");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libwpd", rpm:"libwpd~0.8.7~3.1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd-devel", rpm:"libwpd-devel~0.8.7~3.1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd-tools", rpm:"libwpd-tools~0.8.7~3.1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
