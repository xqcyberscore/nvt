###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for hpijs3 CESA-2013:0133 centos5 
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
tag_insight = "Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers for
  Hewlett-Packard (HP) printers and multifunction peripherals.

  It was found that the HP CUPS (Common UNIX Printing System) fax filter in
  HPLIP created a temporary file in an insecure way. A local attacker could
  use this flaw to perform a symbolic link attack, overwriting arbitrary
  files accessible to a process using the fax filter (such as the
  hp3-sendfax tool). (CVE-2011-2722)
  
  This update also fixes the following bug:
  
  * Previous modifications of the hplip3 package to allow it to be installed
  alongside the original hplip package introduced several problems to fax
  support; for example, the hp-sendfax utility could become unresponsive.
  These problems have been fixed with this update. (BZ#501834)
  
  All users of hplip3 are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.";


tag_affected = "hpijs3 on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019115.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881570");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:36 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2011-2722");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_xref(name: "CESA", value: "2013:0133");
  script_name("CentOS Update for hpijs3 CESA-2013:0133 centos5 ");

  script_tag(name:"summary", value:"Check for the Version of hpijs3");
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

  if ((res = isrpmvuln(pkg:"hpijs3", rpm:"hpijs3~3.9.8~15.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3", rpm:"hplip3~3.9.8~15.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3-common", rpm:"hplip3-common~3.9.8~15.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3-gui", rpm:"hplip3-gui~3.9.8~15.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3-libs", rpm:"hplip3-libs~3.9.8~15.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsane-hpaio3", rpm:"libsane-hpaio3~3.9.8~15.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
