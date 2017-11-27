###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_3075-01_wget.nasl 7859 2017-11-22 09:05:55Z asteins $
#
# RedHat Update for wget RHSA-2017:3075-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.812056");
  script_version("$Revision: 7859 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 10:05:55 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-27 14:30:52 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-13089", "CVE-2017-13090");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for wget RHSA-2017:3075-01");
  script_tag(name: "summary", value: "Check the version of wget");
  script_tag(name: "vuldetect", value: "Get the installed version with the
  help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The wget packages provide the GNU
  Wget file retrieval utility for HTTP, HTTPS, and FTP protocols.

Security Fix(es):

* A stack-based and a heap-based buffer overflow flaws were found in wget
when processing chunked encoded HTTP responses. By tricking an unsuspecting
user into connecting to a malicious HTTP server, an attacker could exploit
these flaws to potentially execute arbitrary code. (CVE-2017-13089,
CVE-2017-13090)

Red Hat would like to thank the GNU Wget project for reporting these
issues.
");
  script_tag(name: "affected", value: "wget on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:3075-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-October/msg00038.html");
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

  if ((res = isrpmvuln(pkg:"wget", rpm:"wget~1.14~15.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wget-debuginfo", rpm:"wget-debuginfo~1.14~15.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
