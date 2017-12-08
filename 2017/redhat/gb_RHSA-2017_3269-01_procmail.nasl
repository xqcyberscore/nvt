###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3269-01_procmail.nasl 8019 2017-12-07 07:42:09Z santu $
#
# RedHat Update for procmail RHSA-2017:3269-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812315");
  script_version("$Revision: 8019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 08:42:09 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-30 07:33:14 +0100 (Thu, 30 Nov 2017)");
  script_cve_id("CVE-2017-16844");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for procmail RHSA-2017:3269-01");
  script_tag(name: "summary", value: "Check the version of procmail");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "The procmail packages contain a mail 
  processing tool that can be used to create mail servers, mailing lists, sort 
  incoming mail into separate folders or files, preprocess mail, start any program 
  upon mail arrival, or automatically forward selected incoming mail. Security 
  Fix(es): * A heap-based buffer overflow flaw was found in procmail's formail 
  utility. A remote attacker could send a specially crafted email that, when 
  processed by formail, could cause formail to crash or, possibly, execute 
  arbitrary code as the user running formail. (CVE-2017-16844) "); 
  script_tag(name: "affected", value: "procmail on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:3269-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-November/msg00037.html");
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

  if ((res = isrpmvuln(pkg:"procmail", rpm:"procmail~3.22~36.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"procmail-debuginfo", rpm:"procmail-debuginfo~3.22~36.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
