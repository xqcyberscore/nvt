###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for jakarta-commons-collections RHSA-2015:2521-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871512");
  script_version("$Revision: 6689 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:50:06 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-12-01 06:13:38 +0100 (Tue, 01 Dec 2015)");
  script_cve_id("CVE-2015-7501");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for jakarta-commons-collections RHSA-2015:2521-01");
  script_tag(name: "summary", value: "Check the version of jakarta-commons-collections");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The Jakarta/Apache Commons Collections
library provides new interfaces, implementations, and utilities to extend the
features of the Java Collections Framework.

It was found that the Apache commons-collections library permitted code
execution when deserializing objects involving a specially constructed
chain of classes. A remote attacker could use this flaw to execute
arbitrary code with the permissions of the application using the
commons-collections library. (CVE-2015-7501)

With this update, deserialization of certain classes in the
commons-collections library is no longer allowed. Applications that require
those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to re-enable
their deserialization.

Further information about this security flaw may be found at:
https://access.redhat.com/solutions/2045023

All users of jakarta-commons-collections are advised to upgrade to these
updated packages, which contain a backported patch to correct this issue.
All running applications using the commons-collections library must be
restarted for the update to take effect.
");
  script_tag(name: "affected", value: "jakarta-commons-collections on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "RHSA", value: "2015:2521-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2015-November/msg00070.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections", rpm:"jakarta-commons-collections~3.2.1~3.5.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
