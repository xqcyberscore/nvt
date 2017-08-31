###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal6-emfield FEDORA-2016-9
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
  script_oid("1.3.6.1.4.1.25623.1.0.807716");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-03-20 06:17:44 +0100 (Sun, 20 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal6-emfield FEDORA-2016-9");
  script_tag(name: "summary", value: "Check the version of drupal6-emfield");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "This extensible module will create fields
  for content types that can be used to display video, image, and audio files
  from various third party providers. When entering the content, the user will
  simply paste the URL or embed code from the third party, and the module will
  automatically determine which content provider is being used. When displaying
  the content, the proper embedding format will be used.

  The module is only an engine, and requires a supported module to function.
  These include 'Embedded Image Field', 'Embedded Video Field' and 'Embedded
  Audio Field'. These modules are included in the contrib folder of the module,
  so they can be easily activated from the module administration page.

  Please note: As of emfield 2.x, provider files for these modules are no longer
  included with the main emfield module, and must be downloaded separately.

  This package provides the following Drupal modules:
  * emaudio
  * embonus
  * emfield
  * emimage
  * eminline
  * emthumb
  * emvideo
  * emwave");

  script_tag(name: "affected", value: "drupal6-emfield on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-9");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-March/179061.html");
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

  if ((res = isrpmvuln(pkg:"drupal6-emfield", rpm:"drupal6-emfield~2.7~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
