###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2012:0079 centos4 
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

  A use-after-free flaw was found in the way Firefox removed nsDOMAttribute
  child nodes. In certain circumstances, due to the premature notification
  of AttributeChildRemoved, a malicious script could possibly use this flaw
  to cause Firefox to crash or, potentially, execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2011-3659)
  
  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-0442)
  
  A flaw was found in the way Firefox parsed Ogg Vorbis media files. A web
  page containing a malicious Ogg Vorbis media file could cause Firefox to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Firefox. (CVE-2012-0444)
  
  A flaw was found in the way Firefox parsed certain Scalable Vector Graphics
  (SVG) image files that contained eXtensible Style Sheet Language
  Transformations (XSLT). A web page containing a malicious SVG image file
  could cause Firefox to crash or, potentially, execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2012-0449)
  
  The same-origin policy in Firefox treated <a  rel= &qt nofollow &qt  href= &qt http://example.com &qt >http://example.com</a> and
  <a  rel= &qt nofollow &qt  href= &qt http://[example.com &qt >http://[example.com</a>] as interchangeable. A malicious script could possibly
  use this flaw to gain access to sensitive information (such as a client's
  IP and user e-mail address, or httpOnly cookies) that may be included in
  HTTP proxy error replies, generated in response to invalid URLs using
  square brackets. (CVE-2011-3670)
  
  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.26. You can find a link to the Mozilla
  advisories in the References section of this erratum.
  
  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.26, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.";

tag_affected = "firefox on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-January/018404.html");
  script_id(881150);
  script_version("$Revision: 8295 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 07:29:18 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:23:02 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2012:0079");
  script_name("CentOS Update for firefox CESA-2012:0079 centos4 ");

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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.26~2.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
