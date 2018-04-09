###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pidgin CESA-2009:1218 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  Federico Muttis of Core Security Technologies discovered a flaw in Pidgin's
  MSN protocol handler. If a user received a malicious MSN message, it was
  possible to execute arbitrary code with the permissions of the user running
  Pidgin. (CVE-2009-2694)
  
  Note: Users can change their privacy settings to only allow messages from
  users on their buddy list to limit the impact of this flaw.
  
  These packages upgrade Pidgin to version 2.5.9. Refer to the Pidgin release
  notes for a full list of changes: http://developer.pidgin.im/wiki/ChangeLog
  
  All Pidgin users should upgrade to these updated packages, which resolve
  this issue. Pidgin must be restarted for this update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "pidgin on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-August/016101.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880737");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2009:1218");
  script_cve_id("CVE-2009-2694");
  script_name("CentOS Update for pidgin CESA-2009:1218 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~1.5.1~4.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
