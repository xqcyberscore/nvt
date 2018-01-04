###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for squirrelmail RHSA-2012:0103-01
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
tag_insight = "SquirrelMail is a standards-based webmail package written in PHP.

  A cross-site scripting (XSS) flaw was found in the way SquirrelMail
  performed the sanitization of HTML style tag content. A remote attacker
  could use this flaw to send a specially-crafted Multipurpose Internet Mail
  Extensions (MIME) message that, when opened by a victim, would lead to
  arbitrary web script execution in the context of their SquirrelMail
  session. (CVE-2011-2023)
  
  Multiple cross-site scripting (XSS) flaws were found in SquirrelMail. A
  remote attacker could possibly use these flaws to execute arbitrary web
  script in the context of a victim's SquirrelMail session. (CVE-2010-4555)
  
  An input sanitization flaw was found in the way SquirrelMail handled the
  content of various HTML input fields. A remote attacker could use this
  flaw to alter user preference values via a newline character contained in
  the input for these fields. (CVE-2011-2752)
  
  It was found that the SquirrelMail Empty Trash and Index Order pages did
  not protect against Cross-Site Request Forgery (CSRF) attacks. If a remote
  attacker could trick a user, who was logged into SquirrelMail, into
  visiting a specially-crafted URL, the attacker could empty the victim's
  trash folder or alter the ordering of the columns on the message index
  page. (CVE-2011-2753)
  
  SquirrelMail was allowed to be loaded into an HTML sub-frame, allowing a
  remote attacker to perform a clickjacking attack against logged in users
  and possibly gain access to sensitive user data. With this update, the
  SquirrelMail main frame can only be loaded into the top most browser frame.
  (CVE-2010-4554)
  
  A flaw was found in the way SquirrelMail handled failed log in attempts. A
  user preference file was created when attempting to log in with a password
  containing an 8-bit character, even if the username was not valid. A
  remote attacker could use this flaw to eventually consume all hard disk
  space on the target SquirrelMail server. (CVE-2010-2813)
  
  A flaw was found in the SquirrelMail Mail Fetch plug-in. If an
  administrator enabled this plug-in, a SquirrelMail user could use this flaw
  to port scan the local network the server was on. (CVE-2010-1637)
  
  Users of SquirrelMail should upgrade to this updated package, which
  contains backported patches to correct these issues.";

tag_affected = "squirrelmail on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00021.html");
  script_id(870543);
  script_version("$Revision: 8273 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 07:29:19 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-02-13 16:28:49 +0530 (Mon, 13 Feb 2012)");
  script_cve_id("CVE-2010-1637", "CVE-2010-2813", "CVE-2010-4554", "CVE-2010-4555",
                "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2012:0103-01");
  script_name("RedHat Update for squirrelmail RHSA-2012:0103-01");

  script_tag(name: "summary" , value: "Check for the Version of squirrelmail");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.el5_7.13", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~18.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
