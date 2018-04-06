###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql84 CESA-2011:1378 centos5 x86_64
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
tag_insight = "PostgreSQL is an advanced object-relational database management system
  (DBMS).

  A signedness issue was found in the way the crypt() function in the
  PostgreSQL pgcrypto module handled 8-bit characters in passwords when using
  Blowfish hashing. Up to three characters immediately preceding a non-ASCII
  character (one with the high bit set) had no effect on the hash result,
  thus shortening the effective password length. This made brute-force
  guessing more efficient as several different passwords were hashed to the
  same value. (CVE-2011-2483)
  
  Note: Due to the CVE-2011-2483 fix, after installing this update some users
  may not be able to log in to applications that store user passwords, hashed
  with Blowfish using the PostgreSQL crypt() function, in a back-end
  PostgreSQL database. Unsafe processing can be re-enabled for specific
  passwords (allowing affected users to log in) by changing their hash prefix
  to &quot;$2x$&quot;.
  
  These updated postgresql84 packages upgrade PostgreSQL to version 8.4.9.
  Refer to the PostgreSQL Release Notes for a full list of changes:
  
  <a  rel= &qt nofollow &qt  href= &qt http://www.postgresql.org/docs/8.4/static/release.html &qt >http://www.postgresql.org/docs/8.4/static/release.html</a>
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct this issue. If the postgresql service is running, it will be
  automatically restarted after installing this update.";

tag_affected = "postgresql84 on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-October/018118.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881408");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:48:36 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2483");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "CESA", value: "2011:1378");
  script_name("CentOS Update for postgresql84 CESA-2011:1378 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of postgresql84");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"postgresql84", rpm:"postgresql84~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-contrib", rpm:"postgresql84-contrib~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-devel", rpm:"postgresql84-devel~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-docs", rpm:"postgresql84-docs~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-libs", rpm:"postgresql84-libs~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plperl", rpm:"postgresql84-plperl~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plpython", rpm:"postgresql84-plpython~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-pltcl", rpm:"postgresql84-pltcl~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-python", rpm:"postgresql84-python~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-server", rpm:"postgresql84-server~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-tcl", rpm:"postgresql84-tcl~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-test", rpm:"postgresql84-test~8.4.9~1.el5_7.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
