###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openstack-glance FEDORA-2013-1930
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
tag_insight = "OpenStack Image Service (code-named Glance) provides discovery, registration,
  and delivery services for virtual disk images. The Image Service API server
  provides a standard REST interface for querying information about virtual disk
  images stored in a variety of back-end stores, including OpenStack Object
  Storage. Clients can register new virtual disk images with the Image Service,
  query for information on publicly available disk images, and use the Image
  Service's client library for streaming virtual disk images.

  This package contains the API and registry servers.";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "openstack-glance on Fedora 18";




if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098722.html");
  script_id(865351);
  script_version("$Revision: 8672 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:39:18 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-02-15 11:14:09 +0530 (Fri, 15 Feb 2013)");
  script_cve_id("CVE-2013-0212");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-1930");
  script_name("Fedora Update for openstack-glance FEDORA-2013-1930");

  script_tag(name: "summary" , value: "Check for the Version of openstack-glance");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"openstack-glance", rpm:"openstack-glance~2012.2.3~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
