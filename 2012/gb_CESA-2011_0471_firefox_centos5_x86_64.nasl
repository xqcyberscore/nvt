###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2011:0471 centos5 x86_64
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
tag_insight = "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could possibly lead to arbitrary code
  execution with the privileges of the user running Firefox. (CVE-2011-0080,
  CVE-2011-0081)
  
  An arbitrary memory write flaw was found in the way Firefox handled
  out-of-memory conditions. If all memory was consumed when a user visited a
  malicious web page, it could possibly lead to arbitrary code execution
  with the privileges of the user running Firefox. (CVE-2011-0078)
  
  An integer overflow flaw was found in the way Firefox handled the HTML
  frameset tag. A web page with a frameset tag containing large values for
  the &quot;rows&quot; and &quot;cols&quot; attributes could trigger this flaw, possibly leading
  to arbitrary code execution with the privileges of the user running
  Firefox. (CVE-2011-0077)
  
  A flaw was found in the way Firefox handled the HTML iframe tag. A web page
  with an iframe tag containing a specially-crafted source address could
  trigger this flaw, possibly leading to arbitrary code execution with the
  privileges of the user running Firefox. (CVE-2011-0075)
  
  A flaw was found in the way Firefox displayed multiple marquee elements. A
  malformed HTML document could cause Firefox to execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2011-0074)
  
  A flaw was found in the way Firefox handled the nsTreeSelection element.
  Malformed content could cause Firefox to execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2011-0073)
  
  A use-after-free flaw was found in the way Firefox appended frame and
  iframe elements to a DOM tree when the NoScript add-on was enabled.
  Malicious HTML content could cause Firefox to execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2011-0072)
  
  A directory traversal flaw was found in the Firefox resource:// protocol
  handler. Malicious content could cause Firefox to access arbitrary files
  accessible to the user running Firefox. (CVE-2011-0071)
  
  A double free flaw was found in the way Firefox handled
  &quot;application/http-index-format&quot; documents. A malformed HTTP response could
  cause Firefox to execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2011-0070)
  
  A flaw was found in the way Firefox handled certain JavaScript cross-domain
  requests. If malicious content generated a large number of cross-domain
  JavaScript reque ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "firefox on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-April/017461.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881346");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:30:49 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069",
                "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073",
                "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078",
                "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2011:0471");
  script_name("CentOS Update for firefox CESA-2011:0471 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of firefox");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.17~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.2.17~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.2.17~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
