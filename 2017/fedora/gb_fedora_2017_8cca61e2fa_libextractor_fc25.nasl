###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_8cca61e2fa_libextractor_fc25.nasl 7629 2017-11-02 12:23:12Z santu $
#
# Fedora Update for libextractor FEDORA-2017-8cca61e2fa
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
  script_oid("1.3.6.1.4.1.25623.1.0.873549");
  script_version("$Revision: 7629 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-02 13:23:12 +0100 (Thu, 02 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 18:05:29 +0530 (Thu, 02 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libextractor FEDORA-2017-8cca61e2fa");
  script_tag(name: "summary", value: "Check the version of libextractor");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "libextractor is a simple library for 
keyword extraction.  libextractor does not support all formats but supports a 
simple plugging mechanism such that you can quickly add extractors for additional 
formats, even without recompiling libextractor.  libextractor typically ships 
with a dozen helper-libraries that can be used to obtain keywords from common
file-types.

libextractor is a part of the GNU project ('http://www.gnu.org/').
");
  script_tag(name: "affected", value: "libextractor on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-8cca61e2fa");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6TEMZKQZ6AZNVSJ4N6AUTPVPYCSMOP3E");
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

  if ((res = isrpmvuln(pkg:"libextractor", rpm:"libextractor~1.6~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
