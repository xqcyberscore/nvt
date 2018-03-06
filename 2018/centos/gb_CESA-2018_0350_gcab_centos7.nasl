###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0350_gcab_centos7.nasl 9023 2018-03-05 07:08:45Z cfischer $
#
# CentOS Update for gcab CESA-2018:0350 centos7 
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
  script_oid("1.3.6.1.4.1.25623.1.0.882844");
  script_version("$Revision: 9023 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-05 08:08:45 +0100 (Mon, 05 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-01 08:13:33 +0100 (Thu, 01 Mar 2018)");
  script_cve_id("CVE-2018-5345");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for gcab CESA-2018:0350 centos7 ");
  script_tag(name: "summary", value: "Check the version of gcab");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The gcab package contains a utility for 
managing the Cabinet archives. It can list, extract, and create Microsoft 
cabinet (.cab) files.

Security Fix(es):

* gcab: Extracting malformed .cab files causes stack smashing potentially
leading to arbitrary code execution (CVE-2018-5345)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.
");
  script_tag(name: "affected", value: "gcab on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "CESA", value: "2018:0350");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2018-February/022766.html");
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

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"gcab", rpm:"gcab~0.7~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcab1", rpm:"libgcab1~0.7~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcab1-devel", rpm:"libgcab1-devel~0.7~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
