###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss RHSA-2017:1364-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871824");
  script_version("$Revision: 6691 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:51:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-05-30 15:54:36 +0200 (Tue, 30 May 2017)");
  script_cve_id("CVE-2017-7502");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for nss RHSA-2017:1364-01");
  script_tag(name: "summary", value: "Check the version of nss");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Network Security Services (NSS) is a set
  of libraries designed to support the cross-platform development of
  security-enabled client and server applications.

Security Fix(es):

* A null pointer dereference flaw was found in the way NSS handled empty
SSLv2 messages. An attacker could use this flaw to crash a server
application compiled against the NSS library. (CVE-2017-7502)

Bug Fix(es):

* The Network Security Services (NSS) code and Certificate Authority (CA)
list have been updated to meet the recommendations as published with the
latest Mozilla Firefox Extended Support Release (ESR). The updated CA list
improves compatibility with the certificates that are used in the Internet
Public Key Infrastructure (PKI). To avoid certificate validation refusals,
Red Hat recommends installing the updated CA list on June 12, 2017.
(BZ#1448488)
");
  script_tag(name: "affected", value: "nss on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:1364-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-May/msg00044.html");
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

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.28.4~3.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.28.4~3.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.28.4~3.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.28.4~3.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.28.4~3.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
