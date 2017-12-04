###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3263-01_curl.nasl 7968 2017-12-01 08:26:28Z asteins $
#
# RedHat Update for curl RHSA-2017:3263-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812308");
  script_version("$Revision: 7968 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 09:26:28 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-28 07:18:38 +0100 (Tue, 28 Nov 2017)");
  script_cve_id("CVE-2017-1000257");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for curl RHSA-2017:3263-01");
  script_tag(name: "summary", value: "Check the version of curl");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The curl packages provide the libcurl
library and the curl utility for downloading files from servers using various
protocols, including HTTP, FTP, and LDAP.

Security Fix(es):

* A buffer overrun flaw was found in the IMAP handler of libcurl. By
tricking an unsuspecting user into connecting to a malicious IMAP server,
an attacker could exploit this flaw to potentially cause information
disclosure or crash the application. (CVE-2017-1000257)

Red Hat would like to thank the Curl project for reporting this issue.
Upstream acknowledges Brian Carpenter and the OSS-Fuzz project as the
original reporters.
");
  script_tag(name: "affected", value: "curl on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:3263-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-November/msg00031.html");
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

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~42.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.29.0~42.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~42.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~42.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
