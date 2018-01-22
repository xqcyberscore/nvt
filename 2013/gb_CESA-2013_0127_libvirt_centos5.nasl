###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2013:0127 centos5 
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
tag_insight = "The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remote management of virtualized
  systems.

  Bus and device IDs were ignored when attempting to attach multiple USB
  devices with identical vendor or product IDs to a guest. This could result
  in the wrong device being attached to a guest, giving that guest root
  access to the device. (CVE-2012-2693)
  
  This update also fixes the following bugs:
  
  * Previously, the libvirtd library failed to set the autostart flags for
  already defined QEMU domains. This bug has been fixed, and the domains can
  now be successfully marked as autostarted. (BZ#675319)
  
  * Prior to this update, the virFileAbsPath() function was not taking into
  account the slash (&quot;/&quot;) directory separator when allocating memory for
  combining the cwd() function and a path. This behavior could lead to a
  memory corruption. With this update, a transformation to the virAsprintff()
  function has been introduced into virFileAbsPath(). As a result, the
  aforementioned behavior no longer occurs. (BZ#680289)
  
  * With this update, a man page of the virsh user interface has been
  enhanced with information on the &quot;domxml-from-native&quot; and
  &quot;domxml-to-native&quot; commands. A correct notation of the format argument has
  been clarified. As a result, confusion is avoided when setting the format
  argument in the described commands. (BZ#783001)
  
  All users of libvirt are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. After installing
  the updated packages, libvirtd will be restarted automatically.";


tag_affected = "libvirt on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019099.html");
  script_id(881576);
  script_version("$Revision: 8466 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 07:58:30 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:56 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2012-2693");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2013:0127");
  script_name("CentOS Update for libvirt CESA-2013:0127 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of libvirt");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~29.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~29.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~29.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
