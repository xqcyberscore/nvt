###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_98e8569b33_dnsdist_fc25.nasl 7075 2017-09-07 11:09:13Z santu $
#
# Fedora Update for dnsdist FEDORA-2017-98e8569b33
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
  script_oid("1.3.6.1.4.1.25623.1.0.873331");
  script_version("$Revision: 7075 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-07 13:09:13 +0200 (Thu, 07 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-02 07:30:34 +0200 (Sat, 02 Sep 2017)");
  script_cve_id("CVE-2016-7069", "CVE-2017-7557");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for dnsdist FEDORA-2017-98e8569b33");
  script_tag(name: "summary", value: "Check the version of dnsdist");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "dnsdist is a highly DNS-, DoS- and 
abuse-aware loadbalancer. Its goal in life is to route traffic to the best 
server, delivering top performance to legitimate users while shunting or 
blocking abusive traffic.");
  script_tag(name: "affected", value: "dnsdist on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-98e8569b33");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GPRPYIAEVOJ72RN2VRHY6MQZK43RE3UV");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.2.0~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
