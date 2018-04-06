###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for dovecot RHSA-2011:0600-01
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
tag_insight = "Dovecot is an IMAP server for Linux, UNIX, and similar operating systems,
  primarily written with security in mind.

  A flaw was found in the way Dovecot handled SIGCHLD signals. If a large
  amount of IMAP or POP3 session disconnects caused the Dovecot master
  process to receive these signals rapidly, it could cause the master process
  to crash. (CVE-2010-3780)

  A flaw was found in the way Dovecot processed multiple Access Control Lists
  (ACL) defined for a mailbox. In some cases, Dovecot could fail to apply the
  more specific ACL entry, possibly resulting in more access being granted to
  the user than intended. (CVE-2010-3707)

  This update also adds the following enhancement:

  * This erratum upgrades Dovecot to upstream version 2.0.9, providing
  multiple fixes for the &quot;dsync&quot; utility and improving overall performance.
  Refer to the &quot;/usr/share/doc/dovecot-2.0.9/ChangeLog&quot; file after installing
  this update for further information about the changes. (BZ#637056)

  Users of dovecot are advised to upgrade to these updated packages, which
  resolve these issues and add this enhancement. After installing the updated
  packages, the dovecot service will be restarted automatically.";

tag_affected = "dovecot on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-May/msg00022.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870607");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:33:45 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3707", "CVE-2010-3780");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_xref(name: "RHSA", value: "2011:0600-01");
  script_name("RedHat Update for dovecot RHSA-2011:0600-01");

  script_tag(name: "summary" , value: "Check for the Version of dovecot");
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

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.0.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-debuginfo", rpm:"dovecot-debuginfo~2.0.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~2.0.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~2.0.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.0.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
