###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_150762f6be_glusterfs_fc25.nasl 7668 2017-11-06 13:16:04Z santu $
#
# Fedora Update for glusterfs FEDORA-2017-150762f6be
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873559");
  script_version("$Revision: 7668 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-06 14:16:04 +0100 (Mon, 06 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 11:12:55 +0100 (Thu, 02 Nov 2017)");
  script_cve_id("CVE-2017-15096");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for glusterfs FEDORA-2017-150762f6be");
  script_tag(name: "summary", value: "Check the version of glusterfs");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GlusterFS is a distributed file-system 
capable of scaling to several petabytes. It aggregates various storage bricks 
over Infiniband RDMA or TCP/IP interconnect into one large parallel network 
file system. GlusterFS is one of the most sophisticated file systems in terms 
of features and extensibility.  It borrows a powerful concept called Translators 
from GNU Hurd kernel. Much of the code in GlusterFS is in user space and easily 
manageable.

This package includes the glusterfs binary, the glusterfsd daemon and the
libglusterfs and glusterfs translator modules common to both GlusterFS server
and client framework.
");
  script_tag(name: "affected", value: "glusterfs on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-150762f6be");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EZ427VHWI3A2EM4FIEEAN6VT56KM7BNB");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"glusterfs", rpm:"glusterfs~3.10.6~4.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
