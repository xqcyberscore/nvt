###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for sos CESA-2012:0958 centos6 
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
tag_insight = "The sos package contains a set of tools that gather information from system
  hardware, logs and configuration files. The information can then be used
  for diagnostic purposes and debugging.

  The sosreport utility collected the Kickstart configuration file
  (&quot;/root/anaconda-ks.cfg&quot;), but did not remove the root user's password from
  it before adding the file to the resulting archive of debugging
  information. An attacker able to access the archive could possibly use this
  flaw to obtain the root user's password. &quot;/root/anaconda-ks.cfg&quot; usually
  only contains a hash of the password, not the plain text password.
  (CVE-2012-2664)
  
  Note: This issue affected all installations, not only systems installed via
  Kickstart. A &quot;/root/anaconda-ks.cfg&quot; file is created by all installation
  types.
  
  This updated sos package also includes numerous bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Users
  are directed to the Red Hat Enterprise Linux 6.3 Technical Notes for
  information on the most significant of these changes.
  
  All users of sos are advised to upgrade to this updated package, which
  contains backported patches to correct these issues and add these
  enhancements.";

tag_affected = "sos on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-July/018723.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881136");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:20:29 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2664");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "CESA", value: "2012:0958");
  script_name("CentOS Update for sos CESA-2012:0958 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of sos");
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

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~2.2~29.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
