###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1836_plexus-archiver_centos7.nasl 10247 2018-06-19 07:14:03Z santu $
#
# CentOS Update for plexus-archiver CESA-2018:1836 centos7 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882911");
  script_version("$Revision: 10247 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-19 09:14:03 +0200 (Tue, 19 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-15 05:47:33 +0200 (Fri, 15 Jun 2018)");
  script_cve_id("CVE-2018-1002200");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for plexus-archiver CESA-2018:1836 centos7 ");
  script_tag(name:"summary", value:"Check the version of plexus-archiver");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Plexus project provides a full software
  stack for creating and executing software projects. Based on the Plexus
  container, the applications can utilise component-oriented programming to build
  modular, reusable components that can easily be assembled and reused. The
  plexus-archiver component provides functions to create and extract archives.

Security Fix(es):

* plexus-archiver: arbitrary file write vulnerability / arbitrary code
execution using a specially crafted zip file (CVE-2018-1002200)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Danny Grander (Snyk) for reporting this issue.
");
  script_tag(name:"affected", value:"plexus-archiver on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:1836");
  script_xref(name:"URL" , value:"http://lists.centos.org/pipermail/centos-announce/2018-June/022922.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

if(release == NULL){
  exit(0);
}

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"plexus-archiver", rpm:"plexus-archiver~2.4.2~5.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plexus-archiver-javadoc", rpm:"plexus-archiver-javadoc~2.4.2~5.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
