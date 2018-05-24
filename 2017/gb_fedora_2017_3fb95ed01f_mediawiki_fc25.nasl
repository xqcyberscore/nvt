###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mediawiki FEDORA-2017-3fb95ed01f
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872572");
  script_version("$Revision: 9939 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-23 16:50:30 +0200 (Wed, 23 May 2018) $");
  script_tag(name:"creation_date", value:"2017-04-16 06:47:35 +0200 (Sun, 16 Apr 2017)");
  script_cve_id("CVE-2017-0363", "CVE-2017-0364", "CVE-2017-0365", "CVE-2017-0361", 
                "CVE-2017-0362", "CVE-2017-0368", "CVE-2017-0366", "CVE-2017-0370", 
                "CVE-2017-0369", "CVE-2017-0367", "CVE-2017-0372");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mediawiki FEDORA-2017-3fb95ed01f");
  script_tag(name: "summary", value: "Check the version of mediawiki");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "MediaWiki is the software used for Wikipedia 
and the other Wikimedia Foundation websites. Compared to other wikis, it has an 
excellent range of features and support for high-traffic websites using multiple
servers

This package supports wiki farms. Read the instructions for creating wiki
instances under /usr/share/doc/mediawiki/README.RPM.
Remember to remove the config dir after completing the configuration.
");
  script_tag(name: "affected", value: "mediawiki on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-3fb95ed01f");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7CIBK7PEBCFB5CCYEOON63PKYIOO4MRI");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.27.2~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
