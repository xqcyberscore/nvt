###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for squid RHSA-2016:2600-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871712");
  script_version("$Revision: 6690 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:51:07 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-11-04 05:43:43 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-2572",
                "CVE-2016-3948");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for squid RHSA-2016:2600-02");
  script_tag(name: "summary", value: "Check the version of squid");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

The following packages have been upgraded to a newer upstream version:
squid (3.5.20). (BZ#1273942, BZ#1349775)

Security Fix(es):

* Incorrect boundary checks were found in the way squid handled headers in
HTTP responses, which could lead to an assertion failure. A malicious HTTP
server could use this flaw to crash squid using a specially crafted HTTP
response. (CVE-2016-2569, CVE-2016-2570)

* It was found that squid did not properly handle errors when failing to
parse an HTTP response, possibly leading to an assertion failure. A
malicious HTTP server could use this flaw to crash squid using a specially
crafted HTTP response. (CVE-2016-2571, CVE-2016-2572)

* An incorrect boundary check was found in the way squid handled the Vary
header in HTTP responses, which could lead to an assertion failure. A
malicious HTTP server could use this flaw to crash squid using a specially
crafted HTTP response. (CVE-2016-3948)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section.
");
  script_tag(name: "affected", value: "squid on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2016:2600-02");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00036.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.20~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.5.20~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-migration-script", rpm:"squid-migration-script~3.5.20~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
