###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xstream FEDORA-2016-250042
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807953");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-04-27 05:18:36 +0200 (Wed, 27 Apr 2016)");
  script_cve_id("CVE-2016-3674");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for xstream FEDORA-2016-250042");
  script_tag(name: "summary", value: "Check the version of xstream");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "XStream is a simple library to serialize
  objects to XML and back again. A high level facade is supplied that
  simplifies common use cases. Custom objects can be serialized
  without need for specifying mappings. Speed and low memory
  footprint are a crucial part of the design, making it suitable
  for large object graphs or systems with high message throughput.
  No information is duplicated that can be obtained via reflection.
  This results in XML that is easier to read for humans and more
  compact than native Java serialization. XStream serializes internal
  fields, including private and final. Supports non-public and inner
  classes. Classes are not required to have default constructor.
  Duplicate references encountered in the object-model will be
  maintained. Supports circular references. By implementing an
  interface, XStream can serialize directly to/from any tree
  structure (not just XML). Strategies can be registered allowing
  customization of how particular types are represented as XML.
  When an exception occurs due to malformed XML, detailed diagnostics
  are provided to help isolate and fix the problem.");

  script_tag(name: "affected", value: "xstream on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-250042");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-April/183208.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"xstream", rpm:"xstream~1.4.9~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
