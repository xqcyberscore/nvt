###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1868-01_python.nasl 6855 2017-08-04 13:23:41Z cfischer $
#
# RedHat Update for python RHSA-2017:1868-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871871");
  script_version("$Revision: 6855 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-04 15:23:41 +0200 (Fri, 04 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:42 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2014-9365");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for python RHSA-2017:1868-01");
  script_tag(name: "summary", value: "Check the version of python");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "Python is an interpreted, interactive, 
  object-oriented programming language, which includes modules, classes, 
  exceptions, very high level dynamic data types and dynamic typing. Python 
  supports interfaces to many system calls and libraries, as well as to various 
  windowing systems. Security Fix(es): * The Python standard library HTTP client 
  modules (such as httplib or urllib) did not perform verification of TLS/SSL 
  certificates when connecting to HTTPS servers. A man-in-the-middle attacker 
  could use this flaw to hijack connections and eavesdrop or modify transferred 
  data. (CVE-2014-9365) Note: The Python standard library was updated to enable 
  certificate verification by default. Refer to the Knowledgebase article 2039753 
  linked to in the References section for further details about this change. 
  (BZ#1219110) Additional Changes: For detailed information on changes in this 
  release, see the Red Hat Enterprise Linux 7.4 Release Notes linked from the 
  References section. "); 
  script_tag(name: "affected", value: "python on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:1868-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00021.html");
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

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~58.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.5~58.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.5~58.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~58.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}