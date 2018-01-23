###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for infiniband-diags CESA-2013:0509 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Red Hat Enterprise Linux includes a collection of InfiniBand and iWARP
  utilities, libraries and development packages for writing applications
  that use Remote Direct Memory Access (RDMA) technology.

  A denial of service flaw was found in the way ibacm managed reference
  counts for multicast connections. An attacker could send specially-crafted
  multicast packets that would cause the ibacm daemon to crash.
  (CVE-2012-4517)
  
  It was found that the ibacm daemon created some files with world-writable
  permissions. A local attacker could use this flaw to overwrite the
  contents of the ibacm.log or ibacm.port file, allowing them to mask
  certain actions from the log or cause ibacm to run on a non-default port.
  (CVE-2012-4518)
  
  CVE-2012-4518 was discovered by Florian Weimer of the Red Hat Product
  Security Team and Kurt Seifried of the Red Hat Security Response Team.
  
  The InfiniBand/iWARP/RDMA stack components have been upgraded to more
  recent upstream versions.
  
  This update also fixes the following bugs:
  
  * Previously, the &quot;ibnodes -h&quot; command did not show a proper usage message.
  With this update the problem is fixed and &quot;ibnodes -h&quot; now shows the
  correct usage message. (BZ#818606)
  
  * Previously, the ibv_devinfo utility erroneously showed iWARP cxgb3
  hardware's physical state as invalid even when the device was working. For
  iWARP hardware, the phys_state field has no meaning. This update patches
  the utility to not print out anything for this field when the hardware is
  iWARP hardware. (BZ#822781)
  
  * Prior to the release of Red Hat Enterprise Linux 6.3, the kernel created
  the InfiniBand device files in the wrong place and a udev rules file was
  used to force the devices to be created in the proper place. With the
  update to 6.3, the kernel was fixed to create the InfiniBand device files
  in the proper place, and so the udev rules file was removed as no longer
  being necessary. However, a bug in the kernel device creation meant that,
  although the devices were now being created in the right place, they had
  incorrect permissions. Consequently, when users attempted to run an RDMA
  application as a non-root user, the application failed to get the necessary
  permissions to use the RDMA device and the application terminated. This
  update puts a new udev rules file in place. It no longer attempts to create
  the InfiniBand devices since they already exist, but it does correct the
  device permissions on the files. (BZ#834428)
  
  * Previously, using the &quot;perfquery -C&quot; command with a host name caused th ... 

  Description truncated, for more information please check the Reference URL";


tag_affected = "infiniband-diags on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-March/019350.html");
  script_id(881641);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:19 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-4517", "CVE-2012-4518");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2013:0509");
  script_name("CentOS Update for infiniband-diags CESA-2013:0509 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of infiniband-diags");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"infiniband-diags", rpm:"infiniband-diags~1.5.12~5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infiniband-diags-devel", rpm:"infiniband-diags-devel~1.5.12~5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infiniband-diags-devel-static", rpm:"infiniband-diags-devel-static~1.5.12~5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
