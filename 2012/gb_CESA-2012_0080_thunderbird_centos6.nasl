###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2012:0080 centos6 
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
tag_insight = "Mozilla Thunderbird is a standalone mail and newsgroup client.

  A use-after-free flaw was found in the way Thunderbird removed
  nsDOMAttribute child nodes. In certain circumstances, due to the premature
  notification of AttributeChildRemoved, a malicious script could possibly
  use this flaw to cause Thunderbird to crash or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2011-3659)
  
  Several flaws were found in the processing of malformed content. An HTML
  mail message containing malicious content could cause Thunderbird to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running Thunderbird. (CVE-2012-0442)
  
  A flaw was found in the way Thunderbird parsed certain Scalable Vector
  Graphics (SVG) image files that contained eXtensible Style Sheet Language
  Transformations (XSLT). An HTML mail message containing a malicious SVG
  image file could cause Thunderbird to crash or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2012-0449)
  
  The same-origin policy in Thunderbird treated <a  rel= &qt nofollow &qt  href= &qt http://example.com &qt >http://example.com</a> and
  <a  rel= &qt nofollow &qt  href= &qt http://[example.com &qt >http://[example.com</a>] as interchangeable. A malicious script could possibly
  use this flaw to gain access to sensitive information (such as a client's
  IP and user e-mail address, or httpOnly cookies) that may be included in
  HTTP proxy error replies, generated in response to invalid URLs using
  square brackets. (CVE-2011-3670)
  
  Note: The CVE-2011-3659 and CVE-2011-3670 issues cannot be exploited by a
  specially-crafted HTML mail message as JavaScript is disabled by default
  for mail messages. It could be exploited another way in Thunderbird, for
  example, when viewing the full remote content of an RSS feed.
  
  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Thunderbird 3.1.18. You can find a link to the Mozilla
  advisories in the References section of this erratum.
  
  All Thunderbird users should upgrade to these updated packages, which
  contain Thunderbird version 3.1.18, which corrects these issues. After
  installing the update, Thunderbird must be restarted for the changes to
  take effect.";

tag_affected = "thunderbird on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-February/018406.html");
  script_id(881210);
  script_version("$Revision: 8253 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 07:29:51 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:46:02 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0449");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2012:0080");
  script_name("CentOS Update for thunderbird CESA-2012:0080 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of thunderbird");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~3.1.18~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
