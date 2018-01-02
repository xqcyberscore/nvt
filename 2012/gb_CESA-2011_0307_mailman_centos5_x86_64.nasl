###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mailman CESA-2011:0307 centos5 x86_64
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
tag_insight = "Mailman is a program used to help manage email discussion lists.

  Multiple input sanitization flaws were found in the way Mailman displayed
  usernames of subscribed users on certain pages. If a user who is subscribed
  to a mailing list were able to trick a victim into visiting one of those
  pages, they could perform a cross-site scripting (XSS) attack against the
  victim. (CVE-2011-0707)
  
  Multiple input sanitization flaws were found in the way Mailman displayed
  mailing list information. A mailing list administrator could use this flaw
  to conduct a cross-site scripting (XSS) attack against victims viewing a
  list's &quot;listinfo&quot; page. (CVE-2008-0564, CVE-2010-3089)
  
  Red Hat would like to thank Mark Sapiro for reporting the CVE-2011-0707 and
  CVE-2010-3089 issues.
  
  Users of mailman should upgrade to this updated package, which contains
  backported patches to correct these issues.";

tag_affected = "mailman on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-April/017372.html");
  script_id(881375);
  script_version("$Revision: 8265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 07:29:23 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:37:29 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2008-0564", "CVE-2010-3089", "CVE-2011-0707");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "CESA", value: "2011:0307");
  script_name("CentOS Update for mailman CESA-2011:0307 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of mailman");
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

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.9~6.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
