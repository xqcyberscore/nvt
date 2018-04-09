###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for sos CESA-2013:1121 centos5 
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
tag_insight = "The sos package contains a set of tools that gather information from system
hardware, logs and configuration files. The information can then be used
for diagnostic purposes and debugging.

The sosreport utility collected the Kickstart configuration file
('/root/anaconda-ks.cfg'), but did not remove the root user's password from
it before adding the file to the resulting archive of debugging
information. An attacker able to access the archive could possibly use this
flaw to obtain the root user's password. '/root/anaconda-ks.cfg' usually
only contains a hash of the password, not the plain text password.
(CVE-2012-2664)

Note: This issue affected all installations, not only systems installed via
Kickstart. A '/root/anaconda-ks.cfg' file is created by all installation
types.

The utility also collects yum repository information from
'/etc/yum.repos.d' which in uncommon configurations may contain passwords.
Any http_proxy password specified in these files will now be automatically
removed. Passwords embedded within URLs in these files should be manually
removed or the files excluded from the archive.

All users of sos are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881767");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-01 18:43:21 +0530 (Thu, 01 Aug 2013)");
  script_cve_id("CVE-2012-2664");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for sos CESA-2013:1121 centos5 ");


  tag_affected = "sos on CentOS 5";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1121");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-July/019885.html");
  script_tag(name:"summary", value:"Check for the Version of sos");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~1.7~9.62.el5_9.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
