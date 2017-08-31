###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openssl RHSA-2016:1137-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871625");
  script_version("$Revision: 6690 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:51:07 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:09 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2016-2108");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssl RHSA-2016:1137-01");
  script_tag(name: "summary", value: "Check the version of openssl");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols, as well
as a full-strength general-purpose cryptography library.

Security Fix(es):

* A flaw was found in the way OpenSSL encoded certain ASN.1 data
structures. An attacker could use this flaw to create a specially crafted
certificate which, when verified or re-encoded by OpenSSL, could cause it
to crash, or execute arbitrary code using the permissions of the user
running an application compiled against the OpenSSL library.
(CVE-2016-2108)

Red Hat would like to thank the OpenSSL project for reporting this issue.
Upstream acknowledges Huzaifa Sidhpurwala (Red Hat), Hanno Bck, and David
Benjamin (Google) as the original reporters.
");
  script_tag(name: "affected", value: "openssl on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2016:1137-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2016-May/msg00051.html");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~40.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8e~40.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~40.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~40.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
