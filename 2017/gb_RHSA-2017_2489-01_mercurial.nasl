###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2489-01_mercurial.nasl 7466 2017-10-18 05:09:06Z teissa $
#
# RedHat Update for mercurial RHSA-2017:2489-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871888");
  script_version("$Revision: 7466 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-18 07:09:06 +0200 (Wed, 18 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-08-18 07:32:00 +0200 (Fri, 18 Aug 2017)");
  script_cve_id("CVE-2017-1000115", "CVE-2017-1000116");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mercurial RHSA-2017:2489-01");
  script_tag(name: "summary", value: "Check the version of mercurial");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "Mercurial is a fast, lightweight source 
  control management system designed for efficient handling of very large 
  distributed projects. Security Fix(es): * A vulnerability was found in the way 
  Mercurial handles path auditing and caches the results. An attacker could abuse 
  a repository with a series of commits mixing symlinks and regular 
  files/directories to trick Mercurial into writing outside of a given repository. 
  (CVE-2017-1000115) * A shell command injection flaw related to the handling of 
  'ssh' URLs has been discovered in Mercurial. This can be exploited to execute 
  shell commands with the privileges of the user running the Mercurial client, for 
  example, when performing a 'checkout' or 'update' action on a sub-repository 
  within a malicious repository or a legitimate repository containing a malicious 
  commit. (CVE-2017-1000116) Red Hat would like to thank the Mercurial Security 
  Team for reporting CVE-2017-1000115 and the Subversion Team for reporting 
  CVE-2017-1000116. "); 
  script_tag(name: "affected", value: "mercurial
on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:2489-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00069.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"mercurial", rpm:"mercurial~2.6.2~8.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mercurial-debuginfo", rpm:"mercurial-debuginfo~2.6.2~8.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
