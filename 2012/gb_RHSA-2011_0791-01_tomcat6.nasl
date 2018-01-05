###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tomcat6 RHSA-2011:0791-01
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
tag_insight = "Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  It was found that web applications could modify the location of the Tomcat
  host's work directory. As web applications deployed on Tomcat have read and
  write access to this directory, a malicious web application could use this
  flaw to trick Tomcat into giving it read and write access to an arbitrary
  directory on the file system. (CVE-2010-3718)

  A cross-site scripting (XSS) flaw was found in the Manager application,
  used for managing web applications on Tomcat. If a remote attacker could
  trick a user who is logged into the Manager application into visiting a
  specially-crafted URL, the attacker could perform Manager application tasks
  with the privileges of the logged in user. (CVE-2010-4172)

  A second cross-site scripting (XSS) flaw was found in the Manager
  application. A malicious web application could use this flaw to conduct an
  XSS attack, leading to arbitrary web script execution with the privileges
  of victims who are logged into and viewing Manager application web pages.
  (CVE-2011-0013)

  This update also fixes the following bugs:

  * A bug in the &quot;tomcat6&quot; init script prevented additional Tomcat instances
  from starting. As well, running &quot;service tomcat6 start&quot; caused
  configuration options applied from &quot;/etc/sysconfig/tomcat6&quot; to be
  overwritten with those from &quot;/etc/tomcat6/tomcat6.conf&quot;. With this update,
  multiple instances of Tomcat run as expected. (BZ#636997)

  * The &quot;/usr/share/java/&quot; directory was missing a symbolic link to the
  &quot;/usr/share/tomcat6/bin/tomcat-juli.jar&quot; library. Because this library was
  mandatory for certain operations (such as running the Jasper JSP
  precompiler), the &quot;build-jar-repository&quot; command was unable to compose a
  valid classpath. With this update, the missing symbolic link has been
  added. (BZ#661244)

  * Previously, the &quot;tomcat6&quot; init script failed to start Tomcat with a &quot;This
  account is currently not available.&quot; message when Tomcat was configured to
  run under a user that did not have a valid shell configured as a login
  shell. This update modifies the init script to work correctly regardless of
  the daemon user's login shell. Additionally, these new tomcat6 packages now
  set &quot;/sbin/nologin&quot; as the login shell for the &quot;tomcat&quot; user upon
  installation, as recommended by deployment best practices. (BZ#678671 ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "tomcat6 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-May/msg00026.html");
  script_id(870626);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:35:19 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3718", "CVE-2010-4172", "CVE-2011-0013");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "RHSA", value: "2011:0791-01");
  script_name("RedHat Update for tomcat6 RHSA-2011:0791-01");

  script_tag(name: "summary" , value: "Check for the Version of tomcat6");
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

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el-2.1-api", rpm:"tomcat6-el-2.1-api~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1-api", rpm:"tomcat6-jsp-2.1-api~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5-api", rpm:"tomcat6-servlet-2.5-api~6.0.24~33.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
