###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for squirrelmail CESA-2009:1066 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

  A server-side code injection flaw was found in the SquirrelMail
  &quot;map_yp_alias&quot; function. If SquirrelMail was configured to retrieve a
  user's IMAP server address from a Network Information Service (NIS) server
  via the &quot;map_yp_alias&quot; function, an unauthenticated, remote attacker using
  a specially-crafted username could use this flaw to execute arbitrary code
  with the privileges of the web server. (CVE-2009-1579)
  
  Multiple cross-site scripting (XSS) flaws were found in SquirrelMail. An
  attacker could construct a carefully crafted URL, which once visited by an 
  unsuspecting user, could cause the user's web browser to execute malicious
  script in the context of the visited SquirrelMail web page. (CVE-2009-1578)
  
  It was discovered that SquirrelMail did not properly sanitize Cascading
  Style Sheets (CSS) directives used in HTML mail. A remote attacker could
  send a specially-crafted email that could place mail content above
  SquirrelMail's controls, possibly allowing phishing and cross-site
  scripting attacks. (CVE-2009-1581)
  
  Users of squirrelmail should upgrade to this updated package, which
  contains backported patches to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "squirrelmail on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-May/015945.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880772");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2009:1066");
  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1581");
  script_name("CentOS Update for squirrelmail CESA-2009:1066 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of squirrelmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~13.el3.centos.1", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
