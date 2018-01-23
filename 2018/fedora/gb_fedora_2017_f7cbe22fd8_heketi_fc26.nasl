###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_f7cbe22fd8_heketi_fc26.nasl 8493 2018-01-23 06:43:13Z ckuersteiner $
#
# Fedora Update for heketi FEDORA-2017-f7cbe22fd8
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874005");
  script_version("$Revision: 8493 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:43:13 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-11 07:41:09 +0100 (Thu, 11 Jan 2018)");
  script_cve_id("CVE-2017-15103", "CVE-2017-15104");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for heketi FEDORA-2017-f7cbe22fd8");
  script_tag(name: "summary", value: "Check the version of heketi");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Heketi provides a RESTful management 
interface which can be used to manage the life cycle of GlusterFS volumes.  
With Heketi, cloud services like OpenStack Manila, Kubernetes, and OpenShift 
can dynamically provision GlusterFS volumes with any of the supported 
durability types.  Heketi will automatically determine the location for 
bricks across the cluster, making sure to place bricks and its replicas 
across different failure domains.  Heketi also supports any number of 
GlusterFS clusters, allowing cloud services to provide network file 
storage without being limited to a single GlusterFS cluster.
");
  script_tag(name: "affected", value: "heketi on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-f7cbe22fd8");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XJ7UAI64DVKQ5RTMKRMGVFRI3QEN4GRL");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"heketi", rpm:"heketi~5.0.1~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
