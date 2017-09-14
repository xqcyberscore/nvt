###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2388-01_evince.nasl 7088 2017-09-11 05:01:45Z asteins $
#
# RedHat Update for evince RHSA-2017:2388-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871868");
  script_version("$Revision: 7088 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-11 07:01:45 +0200 (Mon, 11 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:04 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-1000083");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for evince RHSA-2017:2388-01");
  script_tag(name: "summary", value: "Check the version of evince");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "The evince packages provide a simple 
  multi-page document viewer for Portable Document Format (PDF), PostScript (PS), 
  Encapsulated PostScript (EPS) files, and, with additional back-ends, also the 
  Device Independent File format (DVI) files. Security Fix(es): * It was found 
  that evince did not properly sanitize the command line which is run to untar 
  Comic Book Tar (CBT) files, thereby allowing command injection. A specially 
  crafted CBT file, when opened by evince or evince-thumbnailer, could execute 
  arbitrary commands in the context of the evince program. (CVE-2017-1000083) Red 
  Hat would like to thank Felix Wilhelm (Google Security Team) for reporting this 
  issue. "); 
  script_tag(name: "affected", value: "evince on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:2388-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00032.html");
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

  if ((res = isrpmvuln(pkg:"evince", rpm:"evince~3.22.1~5.2.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-debuginfo", rpm:"evince-debuginfo~3.22.1~5.2.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-dvi", rpm:"evince-dvi~3.22.1~5.2.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-libs", rpm:"evince-libs~3.22.1~5.2.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-nautilus", rpm:"evince-nautilus~3.22.1~5.2.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}