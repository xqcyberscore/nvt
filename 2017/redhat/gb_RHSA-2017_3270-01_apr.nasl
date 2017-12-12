###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3270-01_apr.nasl 8039 2017-12-08 07:14:34Z teissa $
#
# RedHat Update for apr RHSA-2017:3270-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812316");
  script_version("$Revision: 8039 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 08:14:34 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-30 07:33:10 +0100 (Thu, 30 Nov 2017)");
  script_cve_id("CVE-2017-12613");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for apr RHSA-2017:3270-01");
  script_tag(name: "summary", value: "Check the version of apr");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "The Apache Portable Runtime (APR) is a 
  portability library used by the Apache HTTP Server and other projects. It 
  provides a free library of C data structures and routines. Security Fix(es): * 
  An out-of-bounds array dereference was found in apr_time_exp_get(). An attacker 
  could abuse an unvalidated usage of this function to cause a denial of service 
  or potentially lead to data leak. (CVE-2017-12613) "); 
  script_tag(name: "affected", value: "apr on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:3270-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-November/msg00038.html");
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

  if ((res = isrpmvuln(pkg:"apr", rpm:"apr~1.4.8~3.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-debuginfo", rpm:"apr-debuginfo~1.4.8~3.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-devel", rpm:"apr-devel~1.4.8~3.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"apr", rpm:"apr~1.3.9~5.el6_9.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-debuginfo", rpm:"apr-debuginfo~1.3.9~5.el6_9.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-devel", rpm:"apr-devel~1.3.9~5.el6_9.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
