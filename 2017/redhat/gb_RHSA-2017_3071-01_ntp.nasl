###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3071-01_ntp.nasl 7604 2017-11-01 06:48:12Z asteins $
#
# RedHat Update for ntp RHSA-2017:3071-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812055");
  script_version("$Revision: 7604 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-01 07:48:12 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-27 14:30:25 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ntp RHSA-2017:3071-01");
  script_tag(name: "summary", value: "Check the version of ntp");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The Network Time Protocol (NTP) is used
  to synchronize a computer's time with another referenced time source. These
  packages include the ntpd service which continuously adjusts system time and
  utilities used to query and configure the ntpd service.

Security Fix(es):

* Two vulnerabilities were discovered in the NTP server's parsing of
configuration directives. A remote, authenticated attacker could cause ntpd
to crash by sending a crafted message. (CVE-2017-6463, CVE-2017-6464)

* A vulnerability was found in NTP, in the parsing of packets from the
/dev/datum device. A malicious device could send crafted messages, causing
ntpd to crash. (CVE-2017-6462)

Red Hat would like to thank the NTP project for reporting these issues.
Upstream acknowledges Cure53 as the original reporter of these issues.
");
  script_tag(name: "affected", value: "ntp on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:3071-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-October/msg00037.html");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~12.el6_9.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~12.el6_9.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~12.el6_9.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
