###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for curl RHSA-2013:0771-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "cURL provides the libcurl library and a command line tool for downloading
  files from servers using various protocols, including HTTP, FTP, and LDAP.

  A flaw was found in the way libcurl matched domains associated with
  cookies. This could lead to cURL or an application linked against libcurl
  sending the wrong cookie if only part of the domain name matched the domain
  associated with the cookie, disclosing the cookie to unrelated hosts.
  (CVE-2013-1944)

  Red Hat would like to thank the cURL project for reporting this issue.
  Upstream acknowledges YAMADA Yasuharu as the original reporter.

  Users of curl should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running applications using
  libcurl must be restarted for the update to take effect.";


tag_affected = "curl on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(870986);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:17:48 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-1944");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for curl RHSA-2013:0771-01");

  script_xref(name: "RHSA", value: "2013:0771-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-April/msg00036.html");
  script_tag(name: "summary" , value: "Check for the Version of curl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.19.7~36.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.19.7~36.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.19.7~36.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.19.7~36.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.15.5~16.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.15.5~16.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-devel", rpm:"curl-devel~7.15.5~16.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
