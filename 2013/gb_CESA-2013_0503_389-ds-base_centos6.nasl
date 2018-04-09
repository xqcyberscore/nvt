###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for 389-ds-base CESA-2013:0503 centos6 
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
tag_insight = "The 389-ds-base packages provide 389 Directory Server, which is an LDAPv3
  compliant server. The base packages include the Lightweight Directory
  Access Protocol (LDAP) server and command-line utilities for server
  administration.

  A flaw was found in the way 389 Directory Server enforced ACLs after
  performing an LDAP modify relative distinguished name (modrdn) operation.
  After modrdn was used to move part of a tree, the ACLs defined on the moved
  (Distinguished Name) were not properly enforced until the server was
  restarted. This could allow LDAP users to access information that should be
  restricted by the defined ACLs. (CVE-2012-4450)
  
  This issue was discovered by Noriko Hosoi of Red Hat.
  
  These updated 389-ds-base packages include numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 6.4
  Technical Notes, linked to in the References, for information on the most
  significant of these changes.
  
  All users of 389-ds-base are advised to upgrade to these updated packages,
  which correct this issue and provide numerous bug fixes and enhancements.
  After installing this update, the 389 server service will be restarted
  automatically.";


tag_affected = "389-ds-base on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-March/019278.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881658");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-12 10:01:08 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-4450");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2013:0503");
  script_name("CentOS Update for 389-ds-base CESA-2013:0503 centos6 ");

  script_tag(name:"summary", value:"Check for the Version of 389-ds-base");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~11.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
