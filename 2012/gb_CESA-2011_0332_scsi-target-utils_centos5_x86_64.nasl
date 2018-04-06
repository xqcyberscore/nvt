###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for scsi-target-utils CESA-2011:0332 centos5 x86_64
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
tag_insight = "The scsi-target-utils package contains the daemon and tools to set up and
  monitor SCSI targets. Currently, iSCSI software and iSER targets are
  supported.

  A double-free flaw was found in scsi-target-utils' tgtd daemon. A remote
  attacker could trigger this flaw by sending carefully-crafted network
  traffic, causing the tgtd daemon to crash. (CVE-2011-0001)
  
  Red Hat would like to thank Emmanuel Bouillon of NATO C3 Agency for
  reporting this issue.
  
  All scsi-target-utils users should upgrade to this updated package, which
  contains a backported patch to correct this issue. All running
  scsi-target-utils services must be restarted for the update to take effect.";

tag_affected = "scsi-target-utils on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-April/017394.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881367");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:36:49 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0001");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2011:0332");
  script_name("CentOS Update for scsi-target-utils CESA-2011:0332 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of scsi-target-utils");
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

  if ((res = isrpmvuln(pkg:"scsi-target-utils", rpm:"scsi-target-utils~1.0.8~0.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
