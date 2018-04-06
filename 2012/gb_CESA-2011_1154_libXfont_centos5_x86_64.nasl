###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libXfont CESA-2011:1154 centos5 x86_64
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
tag_insight = "The libXfont packages provide the X.Org libXfont runtime library. X.Org is
  an open source implementation of the X Window System.

  A buffer overflow flaw was found in the way the libXfont library, used by
  the X.Org server, handled malformed font files compressed using UNIX
  compress. A malicious, local user could exploit this issue to potentially
  execute arbitrary code with the privileges of the X.Org server.
  (CVE-2011-2895)
  
  Users of libXfont should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. All running X.Org server instances
  must be restarted for the update to take effect.";

tag_affected = "libXfont on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-September/017883.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881355");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:35:01 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2895");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2011:1154");
  script_name("CentOS Update for libXfont CESA-2011:1154 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of libXfont");
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

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.2.2~1.0.4.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.2.2~1.0.4.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
