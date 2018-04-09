###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for squirrelmail CESA-2009:0010 centos4 i386
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
tag_insight = "SquirrelMail is an easy-to-configure, standards-based, webmail package
  written in PHP. It includes built-in PHP support for the IMAP and SMTP
  protocols, and pure HTML 4.0 page-rendering (with no JavaScript required)
  for maximum browser-compatibility, strong MIME support, address books, and
  folder manipulation.

  Ivan Markovic discovered a cross-site scripting (XSS) flaw in SquirrelMail
  caused by insufficient HTML mail sanitization. A remote attacker could send
  a specially-crafted HTML mail or attachment that could cause a user's Web
  browser to execute a malicious script in the context of the SquirrelMail
  session when that email or attachment was opened by the user.
  (CVE-2008-2379)
  
  It was discovered that SquirrelMail allowed cookies over insecure
  connections (ie did not restrict cookies to HTTPS connections). An attacker
  who controlled the communication channel between a user and the
  SquirrelMail server, or who was able to sniff the user's network
  communication, could use this flaw to obtain the user's session cookie, if
  a user made an HTTP request to the server. (CVE-2008-3663)
  
  Note: After applying this update, all session cookies set for SquirrelMail
  sessions started over HTTPS connections will have the &quot;secure&quot; flag set.
  That is, browsers will only send such cookies over an HTTPS connection. If
  needed, you can revert to the previous behavior by setting the
  configuration option &quot;$only_secure_cookies&quot; to &quot;false&quot; 
  in SquirrelMail's /etc/squirrelmail/config.php configuration file.
  
  Users of squirrelmail should upgrade to this updated package, which
  contains backported patches to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "squirrelmail on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-January/015554.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880932");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "CESA", value: "2009:0010");
  script_cve_id("CVE-2008-2379", "CVE-2008-3663");
  script_name("CentOS Update for squirrelmail CESA-2009:0010 centos4 i386");

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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.el4.centos.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
