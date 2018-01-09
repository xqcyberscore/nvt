###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2012:0085-01
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

  A flaw was found in the processing of malformed content. An HTML mail
  message containing malicious content could cause Thunderbird to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Thunderbird. (CVE-2012-0442)

  A malicious script could possibly use this flaw to gain access to sensitive
  information (such as a client's IP and user e-mail address, or httpOnly cookies)
  that may be included in HTTP proxy error replies, generated in response to
  invalid URLs using square brackets. (CVE-2011-3670)

  Note: The CVE-2011-3670 issue cannot be exploited by a specially-crafted
  HTML mail message as JavaScript is disabled by default for mail messages.
  It could be exploited another way in Thunderbird, for example, when viewing
  the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.";

tag_affected = "thunderbird on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00008.html");
  script_id(870538);
  script_version("$Revision: 8313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 08:02:11 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-02-03 11:23:49 +0530 (Fri, 03 Feb 2012)");
  script_cve_id("CVE-2011-3670", "CVE-2012-0442");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2012:0085-01");
  script_name("RedHat Update for thunderbird RHSA-2012:0085-01");

  script_tag(name: "summary" , value: "Check for the Version of thunderbird");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~46.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~1.5.0.12~46.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
