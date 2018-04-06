###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for sssd CESA-2011:0975 centos5 x86_64
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
tag_insight = "The System Security Services Daemon (SSSD) provides a set of daemons to
  manage access to remote directories and authentication mechanisms. It
  provides an NSS and PAM interface toward the system and a pluggable
  back-end system to connect to multiple different account sources. It is
  also the basis to provide client auditing and policy services for projects
  such as FreeIPA.

  A flaw was found in the SSSD PAM responder that could allow a local
  attacker to force SSSD to enter an infinite loop via a carefully-crafted
  packet. With SSSD unresponsive, legitimate users could be denied the
  ability to log in to the system. (CVE-2010-4341)
  
  Red Hat would like to thank Sebastian Krahmer for reporting this issue.
  
  These updated sssd packages include a number of bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Refer to
  the Red Hat Enterprise Linux 5.7 Technical Notes for information about
  these changes:
  
  <a  rel= &qt nofollow &qt  href= &qt https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/5.7_Tech &qt >https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/5.7_Tech</a>
  nical_Notes/sssd.html#RHSA-2011-0975
  
  All sssd users are advised to upgrade to these updated sssd packages, which
  upgrade SSSD to upstream version 1.5.1 to correct this issue, and fix the
  bugs and add the enhancements noted in the Technical Notes.";

tag_affected = "sssd on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-September/017983.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881420");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:50:09 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4341");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2011:0975");
  script_name("CentOS Update for sssd CESA-2011:0975 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of sssd");
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

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.5.1~37.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.5.1~37.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.5.1~37.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
