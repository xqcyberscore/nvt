###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for sos CESA-2012:0153 centos5 
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
tag_insight = "Sos is a set of tools that gather information about system hardware and
  configuration.

  The sosreport utility incorrectly included Certificate-based Red Hat
  Network private entitlement keys in the resulting archive of debugging
  information. An attacker able to access the archive could use the keys to
  access Red Hat Network content available to the host. This issue did not
  affect users of Red Hat Network Classic. (CVE-2011-4083)
  
  This updated sos package also includes numerous bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Users
  are directed to the Red Hat Enterprise Linux 5.8 Technical Notes, linked
  to in the References, for information on the most significant of these
  changes.
  
  All sos users are advised to upgrade to this updated package, which
  resolves these issues and adds these enhancements.";


tag_affected = "sos on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019179.html");
  script_id(881575);
  script_version("$Revision: 8483 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 07:58:04 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:55 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2011-4083");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "CESA", value: "2012:0153");
  script_name("CentOS Update for sos CESA-2012:0153 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of sos");
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

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~1.7~9.62.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
