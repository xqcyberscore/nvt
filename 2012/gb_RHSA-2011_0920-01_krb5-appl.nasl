###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for krb5-appl RHSA-2011:0920-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The krb5-appl packages provide Kerberos-aware telnet, ftp, rcp, rsh, and
  rlogin clients and servers. While these have been replaced by tools such as
  OpenSSH in most environments, they remain in use in others.

  It was found that gssftp, a Kerberos-aware FTP server, did not properly
  drop privileges. A remote FTP user could use this flaw to gain unauthorized
  read or write access to files that are owned by the root group.
  (CVE-2011-1526)
  
  Red Hat would like to thank the MIT Kerberos project for reporting this
  issue. Upstream acknowledges Tim Zingelman as the original reporter.
  
  All krb5-appl users should upgrade to these updated packages, which contain
  a backported patch to correct this issue.";

tag_affected = "krb5-appl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-July/msg00002.html");
  script_id(870716);
  script_version("$Revision: 8267 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 07:29:17 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:52:48 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1526");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2011:0920-01");
  script_name("RedHat Update for krb5-appl RHSA-2011:0920-01");

  script_tag(name: "summary" , value: "Check for the Version of krb5-appl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"krb5-appl-clients", rpm:"krb5-appl-clients~1.0.1~2.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-appl-debuginfo", rpm:"krb5-appl-debuginfo~1.0.1~2.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-appl-servers", rpm:"krb5-appl-servers~1.0.1~2.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
