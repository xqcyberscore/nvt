###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2017_1793_graphite2_centos7.nasl 6818 2017-07-31 09:55:16Z santu $
# CentOS Update for graphite2 CESA-2017:1793 centos7 
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
  script_oid("1.3.6.1.4.1.25623.1.0.882755");
  script_version("$Revision: 6818 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-31 11:55:16 +0200 (Mon, 31 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-07-22 07:22:25 +0200 (Sat, 22 Jul 2017)");
  script_cve_id("CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", 
                "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for graphite2 CESA-2017:1793 centos7 ");
  script_tag(name: "summary", value: "Check the version of graphite2");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Graphite2 is a project within SIL's 
Non-Roman Script Initiative and Language Software Development groups to 
provide rendering capabilities for complex non-Roman writing systems. 
Graphite can be used to create 'smart fonts' capable of displaying writing 
systems with various complex behaviors. With respect to the Text Encoding 
Model, Graphite handles the 'Rendering' aspect of writing system 
implementation.

The following packages have been upgraded to a newer upstream version:
graphite2 (1.3.10).

Security Fix(es):

* Various vulnerabilities have been discovered in Graphite2. An attacker
able to trick an unsuspecting user into opening specially crafted font
files in an application using Graphite2 could exploit these flaws to
disclose potentially sensitive memory, cause an application crash, or,
possibly, execute arbitrary code. (CVE-2017-7771, CVE-2017-7772,
CVE-2017-7773, CVE-2017-7774, CVE-2017-7775, CVE-2017-7776, CVE-2017-7777,
CVE-2017-7778)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Holger Fuhrmannek and Tyson Smith as the original
reporters of these issues.
");
  script_tag(name: "affected", value: "graphite2 on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "CESA", value: "2017:1793");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2017-July/022510.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"graphite2", rpm:"graphite2~1.3.10~1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"graphite2-devel", rpm:"graphite2-devel~1.3.10~1.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
