###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2423-01_log4j.nasl 6943 2017-08-16 13:35:11Z asteins $
#
# RedHat Update for log4j RHSA-2017:2423-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871877");
  script_version("$Revision: 6943 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-16 15:35:11 +0200 (Wed, 16 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-08 07:19:05 +0200 (Tue, 08 Aug 2017)");
  script_cve_id("CVE-2017-5645");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for log4j RHSA-2017:2423-01");
  script_tag(name: "summary", value: "Check the version of log4j");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Log4j is a tool to help the programmer
output log statements to a variety of output targets.

Security Fix(es):

* It was found that when using remote logging with log4j socket server the
log4j server would deserialize any log event received via TCP or UDP. An
attacker could use this flaw to send a specially crafted log event that,
during deserialization, would execute arbitrary code in the context of the
logger application. (CVE-2017-5645)
");
  script_tag(name: "affected", value: "log4j on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:2423-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00038.html");
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

  if ((res = isrpmvuln(pkg:"log4j", rpm:"log4j~1.2.17~16.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
