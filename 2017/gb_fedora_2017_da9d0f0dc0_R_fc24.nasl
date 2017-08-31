###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for R FEDORA-2017-da9d0f0dc0
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
  script_oid("1.3.6.1.4.1.25623.1.0.872505");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-03-21 05:56:00 +0100 (Tue, 21 Mar 2017)");
  script_cve_id("CVE-2016-8714");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for R FEDORA-2017-da9d0f0dc0");
  script_tag(name: "summary", value: "Check the version of R");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This is a metapackage that provides both 
  core R userspace and all R development components. R is a language and 
  environment for statistical computing and graphics. R is similar to the 
  award-winning S system, which was developed at Bell Laboratories by John 
  Chambers et al. It provides a wide variety of statistical and graphical 
  techniques (linear and nonlinear modelling, statistical tests, time series 
  analysis, classification, clustering, ...). R is designed as a true computer 
  language with control-flow constructions for iteration and alternation, and it 
  allows users to add additional functionality by defining new functions. For 
  computationally intensive tasks, C, C++ and Fortran code can be linked and 
  called at run time. ");
  script_tag(name: "affected", value: "R on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-da9d0f0dc0");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6VDK36EP4GXNSKQFPQDQD5ICMRWCP4RM");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"R", rpm:"R~3.3.3~1.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}